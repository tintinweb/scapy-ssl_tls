#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
'''

server:
    #> openssl s_server -accept 443 -WWW -debug -cipher AES128-SHA
client:
    #> openssl s_client -connect 192.168.220.131:443 -tls1

'''

import sys, os
try:
    from scapy.all import *
except ImportError:
    from scapy import *

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
    import scapy_ssl_tls.ssl_tls_crypto as ssl_tls_crypto
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    import scapy.layers.ssl_tls_crypto as ssl_tls_crypto
    
import socket

class Sniffer(object):
    ''' Sniffer()
        .rdpcap(pcap)
        or
        .sniff()
    '''
    def __init__(self):
        self.ssl_session_map = {}
        
    def _create_context(self, target, keyfile=None):
        self.target = target
        self.keyfile = keyfile
        
        session = ssl_tls_crypto.TLSSessionCtx()
        if keyfile:
            print "* load servers privatekey for ciphertext decryption (RSA key only): %s"%keyfile
            session.rsa_load_keys_from_file(keyfile)
            
        session.printed=False
        self.ssl_session_map[target]=session

    def process_ssl(self, p):
            if not p.haslayer(SSL):
                return
            session = self.ssl_session_map.get((p[IP].dst,p[TCP].dport)) or self.ssl_session_map.get((p[IP].src,p[TCP].sport))
            if not session:
                return
            p_ssl = p[SSL]
            source = (p[IP].src,p[TCP].sport)
            
            if p_ssl.haslayer(SSLv2Record):
                print "SSLv2 not supported - skipping..",repr(p)
                return
            
            if p_ssl.haslayer(TLSServerHello):
                    session.printed=False
                    session.crypto.session.master_secret=None
                    session.match_server = source
                    #reset the session and print it next time
            if p_ssl.haslayer(TLSClientHello):
                session.match_client = source
                
            session.insert(p_ssl) 
            
            if session.crypto.session.master_secret and session.printed==False:
                print repr(session)
                session.printed = True
            
            print "|   %-16s:%-5d => %-16s:%-5d | %s"%(p[IP].src,p[TCP].sport,p[IP].dst,p[TCP].dport,repr(p_ssl))            
            if p.haslayer(TLSCiphertext):
                if source == session.match_client:
                    session.set_mode(server=True)
                elif source == session.match_server:
                    session.set_mode(client=True)
                else:
                    Exception("src packet mismatch: %s"%repr(source))
                p = SSL(str(p_ssl),ctx=session)
                print "|-> %-48s | %s"%("decrypted record",repr(p_ssl))
            #p.show()
            #raw_input()
    
    def sniff(self, target, keyfile=None, iface=None):
        if iface:
            conf.iface=iface
        self._create_context(target=target,keyfile=keyfile)
        while True:
            sniff(filter="host %s and tcp port %d"%(target[0],target[1]),prn=self.process_ssl,store=0,timeout=3)
            
    def rdpcap(self, target, keyfile, pcap):
        self._create_context(target=target,keyfile=keyfile)
        for p in (pkt for pkt in rdpcap(pcap) if pkt.haslayer(SSL)):
            self.process_ssl(p)


def main(target,pcap=None, iface=None, keyfile=None):
    sniffer = Sniffer()
    if pcap:
        print "* pcap ready!"
        # pcap mainloop
        sniffer.rdpcap(target=target, keyfile=keyfile, pcap=pcap)
    else:
        print "* sniffer ready!"
        # sniffer mainloop
        sniffer.sniff(target=target, keyfile=keyfile, iface=iface)

if __name__=="__main__":
    if len(sys.argv)<=3:
        print "USAGE: <host> <port> <inteface or pcap>"
        print "\navailable interfaces:"
        for i in get_if_list():
            print "   * %s"%i
        print "* default"
        exit(1)
        
    pcap=None
    iface=None
    keyfile=None
    if len(sys.argv)>3:
        if os.path.isfile(sys.argv[3]):
            pcap=sys.argv[3]
        elif sys.argv[3] in get_if_list():
            iface=sys.argv[3]
        else:
            raise Exception("Unknown interface or invalid path to pcap.")
    if len(sys.argv)>4:
        if not os.path.isfile(sys.argv[4]):
            raise Exception("PrivateKey File not Found! %s"%sys.argv[4])
        keyfile = sys.argv[4]
        
    main((sys.argv[1],int(sys.argv[2])), iface=iface, pcap=pcap, keyfile=keyfile)