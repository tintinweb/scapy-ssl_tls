#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
'''
An example implementation of a passive TLS security scanner with custom starttls support:

    TLSScanner() generates TLS probe traffic  (optional)
    TLSInfo() passively evaluates the traffic and generates events/warning

    
'''
import sys, os
import concurrent.futures
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    
import socket
from collections import namedtuple
import time

class TCPConnection(object):
    def __init__(self, target, starttls=None):
        last_exception = None
        self.target=target
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for t in xrange(1,4):
            try:
                self._s.connect(target)
                break
            except socket.error, se:
                print "- connection retry %s: %s"%(t,repr(target))
                last_exception = se
        if not self._s:
            raise se
        if starttls:
            self.sendall(starttls.replace("\\r","\r").replace("\\n","\n"))
            self.recvall(timeout=2)

    def sendall(self, pkt, timeout=None):
        if timeout:
            self._s.settimeout(timeout)
        self._s.sendall(str(pkt))

    def recvall(self, size=8192*4, timeout=None):
        resp = []
        if timeout:
            self._s.settimeout(timeout)
        while True:
            try:
                data = self._s.recv(size)t
                if not data:
                    break
                resp.append(data)
            except socket.timeout:
                break
        return SSL(''.join(resp))

class TLSInfo(object):
    def __init__(self):
        self.history = []
        self.events = []
        self.info = namedtuple("info", ['client','server'])
        self.info.client = namedtuple("client", ['versions','ciphers','compressions', 'preferred_ciphers', 'sessions_established', 'heartbeat' ])
        self.info.client.versions = set([])
        self.info.client.ciphers = set([])
        self.info.client.compressions = set([])
        self.info.client.preferred_ciphers = set([])
        self.info.client.sessions_established = 0
        self.info.client.heartbeat = None
        self.info.server = namedtuple("server", ['versions','ciphers','compressions','sessions_established', 'fallback_scsv', 'heartbeat'])
        self.info.server.versions = set([])
        self.info.server.ciphers = set([])
        self.info.server.compressions = set([])
        self.info.server.sessions_established = 0
        self.info.server.fallback_scsv = False
        self.info.server.heartbeat = None
    
    def __str__(self):
        return """<TLSInfo
        packets.processed: %s
        
        client.versions: %s
        client.ciphers: %s
        client.compressions: %s
        client.preferred_ciphers: %s
        client.sessions_established: %s
        client.heartbeat: %s
        
        server.versions: %s
        server.ciphers: %s
        server.compressions: %s
        server.sessions_established: %s
        server.fallback_scsv: %s
        server.heartbeat: %s
>
        """%(len(self.history),
             self.info.client.versions,
             self.info.client.ciphers,
             self.info.client.compressions,
             self.info.client.preferred_ciphers,
             self.info.client.sessions_established,
             self.info.client.heartbeat,
             self.info.server.versions,
             self.info.server.ciphers,
             self.info.server.compressions,
             self.info.server.sessions_established,
             self.info.server.fallback_scsv,
             self.info.server.heartbeat)
        
    def get_events(self):
        events=[]
        for tlsinfo in (self.info.client, self.info.server):
            # test CRIME - compressions offered?
            tmp = tlsinfo.compressions.copy()
            if 0 in tmp:
                tmp.remove(0)
            if len(tmp):
                events.append(("CRIME - %s supports compression"%tlsinfo,tlsinfo.compressions))
            # test RC4
            cipher_namelist = [TLS_CIPHER_SUITES.get(c,c) for c in tlsinfo.ciphers]
            
            tmp = [c for c in cipher_namelist if "EXP" in c.upper()]
            if tmp:
                events.append(("CIPHERS - Export ciphers enabled",tmp))
            tmp = [c for c in cipher_namelist if "RC4" in c.upper()]
            if tmp:
                events.append(("CIPHERS - RC4 ciphers enabled",tmp))
            tmp = [c for c in cipher_namelist if "MD2" in c.upper()]
            if tmp:
                events.append(("CIPHERS - MD2 ciphers enabled",tmp))
            tmp = [c for c in cipher_namelist if "MD4" in c.upper()]
            if tmp:
                events.append(("CIPHERS - MD4 ciphers enabled",tmp))
            tmp = [c for c in cipher_namelist if "MD5" in c.upper()]
            if tmp:
                events.append(("CIPHERS - MD5 ciphers enabled",tmp))
                
            tmp = [c for c in cipher_namelist if "RSA_EXP" in c.upper()]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                events.append(("FREAK - server supports RSA_EXPORT cipher suites",tmp))
            tmp = [c for c in cipher_namelist if "DHE_" in c.upper() and "EXPORT_" in c.upper()]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                events.append(("LOGJAM - server supports weak DH-Group (512) (DHE_*_EXPORT) cipher suites",tmp))
                
            if TLSVersion.SSL_2_0 in tlsinfo.versions:
                events.append(("PROTOCOL VERSION - SSLv2 supported ",tlsinfo.versions))
                
            if TLSVersion.SSL_3_0 in tlsinfo.versions:
                events.append(("PROTOCOL VERSION - SSLv3 supported ",tlsinfo.versions))
                
            if TLSHeartbeatMode.PEER_ALLOWED_TO_SEND == tlsinfo.heartbeat:
                events.append(("HEARTBEAT - enabled (non conclusive heartbleed) ",tlsinfo.versions))
                
        if not self.info.server.fallback_scsv:
            events.append(("DOWNGRADE / POODLE - FALLBACK_SCSV - not honored",self.info.server.fallback_scsv))
        
        return events
        
    def insert(self, pkt, client=None):
        self._process(pkt, client=client)
    
    def _process(self, pkt, client=None):
        if pkt is None:
            return
        if not pkt.haslayer(SSL) and not pkt.haslayer(TLSRecord):
            return
        
        if pkt.haslayer(SSL):
            records = pkt[SSL].records
        else:
            records = [pkt]
            
        for record in records:
            if client or record.haslayer(TLSClientHello):
                tlsinfo = self.info.client
            elif not client or record.haslayer(TLSServerHello):
                tlsinfo = self.info.server
                
            tlsinfo.versions.add(pkt[TLSRecord].version)
        
            if record.haslayer(TLSClientHello):
                tlsinfo.ciphers.update(record[TLSClientHello].cipher_suites)
                tlsinfo.compressions.update(record[TLSClientHello].compression_methods)
                if precordkt[TLSClientHello].cipher_suites:
                    tlsinfo.preferred_ciphers.add(pkt[TLSClientHello].cipher_suites[0])
                    
            if record.haslayer(TLSServerHello):
                tlsinfo.ciphers.add(record[TLSServerHello].cipher_suite)
                tlsinfo.compressions.add(record[TLSServerHello].compression_method)
                if record.haslayer(TLSExtHeartbeat):
                    tlsinfo.heartbeat = record[TLSExtHeartbeat].mode
    
            if record.haslayer(TLSFinished):
                tlsinfo.session.established +=1
            if record.haslayer(TLSHandshake):
                tlsinfo.versions.add(pkt[TLSRecord].version)
                
            if not client and record.haslayer(TLSAlert) and record[TLSAlert].description==TLSAlertDescription.INAPPROPRIATE_FALLBACK:
                tlsinfo.fallback_scsv=True
            # track packet
            self.history.append(pkt)

class TLSScanner(object):
    def __init__(self, workers=10):
        self.workers = workers
        self.capabilities = TLSInfo()
    
    def scan(self, target, starttls=None):
        for scan_method in (f for f in dir(self) if f.startswith("_scan_")):
            print "=> %s"%(scan_method.replace("_scan_",""))
            getattr(self, scan_method)(target, starttls=starttls)
            
    def _scan_compressions(self, target, starttls=None, compression_list=TLS_COMPRESSION_METHODS.keys()): 
        for comp in compression_list:
            # prepare pkt
            pkt = TLSRecord()/TLSHandshake()/TLSClientHello(version=TLSVersion.TLS_1_1, cipher_suites=range(0xfe)[::-1], compression_methods=comp)
            # connect
            try:
                t = TCPConnection(target, starttls=starttls)
                t.sendall(pkt)
                resp = t.recvall(timeout=0.5)
                self.capabilities.insert(resp, client=False)
            except socket.error, se:
                print repr(se)

    
    def _check_cipher(self, target,  cipher_id, starttls=None,version=TLSVersion.TLS_1_0):
        pkt = TLSRecord(version=version)/TLSHandshake()/TLSClientHello(version=version, cipher_suites=[cipher_id])
        try:
            t = TCPConnection(target, starttls=starttls)
            t.sendall(pkt)
            resp = t.recvall(timeout=0.5)
        except socket.error, se:
            print repr(se)
            return None
        return resp
    
    def _scan_accepted_ciphersuites(self, target, starttls=None, cipherlist=TLS_CIPHER_SUITES.keys(), version=TLSVersion.TLS_1_0): 
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            tasks = [executor.submit(self._check_cipher, target, cipher_id, starttls, version) for cipher_id in cipherlist]
            for future in concurrent.futures.as_completed(tasks):
                self.capabilities.insert(future.result(), client=False)

    
    def _scan_supported_protocol_versions(self, target, starttls=None, versionlist=((k,v) for k,v in TLS_VERSIONS.iteritems() if v.startswith("TLS_") or v.startswith("SSL_"))):
        for magic, name in versionlist:
            pkt = TLSRecord(version=magic)/TLSHandshake()/TLSClientHello(version=magic, 
                                                                         cipher_suites=range(0xfe)[::-1],
                                                                         extensions=[TLSExtension()/TLSExtHeartbeat(mode=TLSHeartbeatMode.PEER_ALLOWED_TO_SEND)])
            try:
                # connect
                t = TCPConnection(target, starttls=starttls)
                t.sendall(pkt)
                resp = t.recvall(timeout=0.5)
                self.capabilities.insert(resp, client=False)
            except socket.error, se:
                print repr(se)
            
    def _scan_scsv(self, target, starttls=None): 
        pkt = TLSRecord(version=TLSVersion.TLS_1_1)/TLSHandshake()/TLSClientHello(version=TLSVersion.TLS_1_0, cipher_suites=[TLSCipherSuite.FALLBACK_SCSV]+range(0xfe)[::-1])
        # connect
        try:
            t = TCPConnection(target, starttls=starttls)
            t.sendall(pkt)
            resp = t.recvall(timeout=2)
            self.capabilities.insert(resp, client=False)
        except socket.error, se:
            print repr(se)
    
    def disabled_scan_heartbleed(self, target, starttls=None):
        TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')
        
if __name__=="__main__":
    print __doc__
    if len(sys.argv)<=1:
        print "USAGE: <host> <port> [starttls]"
        print "   starttls ... starttls keyword e.g. 'starttls\n' or 'ssl\n'"
        exit(1)
    starttls = sys.argv[3] if len(sys.argv)>3 else None
    host = sys.argv[1]
    port = int(sys.argv[2])
    workers = 10
    print "Scanning with %s parallel threads..."%workers
    scanner = TLSScanner(workers=workers)
    t_start = time.time()
    scanner.scan((host,port), starttls=starttls)
    print "\n"
    print "[*] Capabilities (Debug)"
    print scanner.capabilities
    print "[*] supported ciphers: %s/%s"%(len(scanner.capabilities.info.server.ciphers),len(TLS_CIPHER_SUITES) )
    print " * " + "\n * ".join(("%s (0x%0.4x)"%(TLS_CIPHER_SUITES.get(c,c),c) for c in  scanner.capabilities.info.server.ciphers))
    print ""
    print "[*] supported protocol versions: %s/%s"%(len(scanner.capabilities.info.server.versions),len(TLS_VERSIONS))
    print " * " + "\n * ".join(("%s (0x%0.4x)"%(TLS_VERSIONS.get(c,c),c) for c in  scanner.capabilities.info.server.versions))
    print ""
    print "[*] supported compressions methods: %s/%s"%(len(scanner.capabilities.info.server.compressions),len(TLS_COMPRESSION_METHODS))
    print " * " + "\n * ".join(("%s (0x%0.4x)"%(TLS_COMPRESSION_METHODS.get(c,c),c) for c in  scanner.capabilities.info.server.compressions))
    print ""
    events = scanner.capabilities.get_events()
    print "[*] Events: %s"%len(events)
    print "* EVENT - " + "\n* EVENT - ".join(e[0] for e in events)
    t_diff = time.time()-t_start
    print ""
    print "Scan took: %ss"%t_diff
