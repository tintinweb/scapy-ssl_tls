#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
"""
An example implementation of a passive TLS security scanner with custom starttls support:

    TLSScanner() generates TLS probe traffic  (optional)
    TLSInfo() passively evaluates the traffic and generates events/warning


"""
from __future__ import print_function
import sys
import concurrent.futures

try:
    from scapy.all import get_if_list, sniff, IP, TCP
except ImportError:
    from scapy import get_if_list, sniff, IP, TCP

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    import scapy_ssl_tls.ssl_tls_keystore as tlsk
except ImportError as ie:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    import scapy.layers.ssl_tls_keystore as tlsk

import socket
from collections import namedtuple
import time


class TCPConnection(object):

    def __init__(self, target, starttls=None):
        last_exception = None
        self.target = target
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for t in xrange(1, 4):
            try:
                self._s.connect(target)
                break
            except socket.error as se:
                print ("- connection retry %s: %s" % (t, repr(target)))
                last_exception = se
        if not self._s:
            raise last_exception
        if starttls:
            self.sendall(starttls.replace("\\r", "\r").replace("\\n", "\n"))
            self.recvall(timeout=2)

    def sendall(self, pkt, timeout=None):
        if timeout:
            self._s.settimeout(timeout)
        self._s.sendall(str(pkt))

    def recvall(self, size=8192 * 4, timeout=None):
        resp = []
        if timeout:
            self._s.settimeout(timeout)
        while True:
            try:
                data = self._s.recv(size)
                if not data:
                    break
                resp.append(data)
            except socket.timeout:
                break
        return SSL(''.join(resp))


class TLSInfo(object):
    # https://en.wikipedia.org/wiki/RSA_numbers
    RSA_MODULI_KNOWN_FACTORED = (1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139,  # RSA-100
                                 # RSA-110
                                 35794234179725868774991807832568455403003778024228226193532908190484670252364677411513516111204504060317568667,
                                 # RSA-120
                                 227010481295437363334259960947493668895875336466084780038173258247009162675779735389791151574049166747880487470296548479,
                                 # RSA-129
                                 114381625757888867669235779976146612010218296721242362562561842935706935245733897830597123563958705058989075147599290026879543541,
                                 # RSA-130
                                 1807082088687404805951656164405905566278102516769401349170127021450056662540244048387341127590812303371781887966563182013214880557,
                                 # RSA-140
                                 21290246318258757547497882016271517497806703963277216278233383215381949984056495911366573853021918316783107387995317230889569230873441936471,
                                 # RSA-150
                                 155089812478348440509606754370011861770654545830995430655466945774312632703463465954363335027577729025391453996787414027003501631772186840890795964683,
                                 # RSA-155
                                 10941738641570527421809707322040357612003732945449205990913842131476349984288934784717997257891267332497625752899781833797076537244027146743531593354333897,
                                 # RSA-160
                                 2152741102718889701896015201312825429257773588845675980170497676778133145218859135673011059773491059602497907111585214302079314665202840140619946994927570407753,
                                 # RSA-170
                                 26062623684139844921529879266674432197085925380486406416164785191859999628542069361450283931914514618683512198164805919882053057222974116478065095809832377336510711545759,
                                 # RSA-576
                                 188198812920607963838697239461650439807163563379417382700763356422988859715234665485319060606504743045317388011303396716199692321205734031879550656996221305168759307650257059,
                                 # RSA-180
                                 191147927718986609689229466631454649812986246276667354864188503638807260703436799058776201365135161278134258296128109200046702912984568752800330221777752773957404540495707851421041,
                                 # RSA-190
                                 1907556405060696491061450432646028861081179759533184460647975622318915025587184175754054976155121593293492260464152630093238509246603207417124726121580858185985938946945490481721756401423481,
                                 # RSA-640
                                 3107418240490043721350750035888567930037346022842727545720161948823206440518081504556346829671723286782437916272838033415471073108501919548529007337724822783525742386454014691736602477652346609,
                                 # RSA-200
                                 27997833911221327870829467638722601621070446786955428537560009929326128400107609345671052955360856061822351910951365788637105954482006576775098580557613579098734950144178863178946295187237869221823983,
                                 # RSA-210
                                 245246644900278211976517663573088018467026787678332759743414451715061600830038587216952208399332071549103626827191679864079776723243005600592035631246561218465817904100131859299619933817012149335034875870551067,
                                 # R SA-704
                                 74037563479561712828046796097429573142593188889231289084936232638972765034028266276891996419625117843995894330502127585370118968098286733173273108930900552505116877063299072396380786710086096962537934650563796359,
                                 # RSA-768
                                 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413,
                                 )

    def __init__(self):
        self.history = []
        self.events = []
        self.info = namedtuple("info", ['client', 'server'])
        self.info.client = namedtuple("client",
                                      ['versions',
                                       'ciphers',
                                       'compressions',
                                       'preferred_ciphers',
                                       'sessions_established',
                                       'heartbeat',
                                       'extensions'])
        self.info.client.versions = set([])
        self.info.client.ciphers = set([])
        self.info.client.compressions = set([])
        self.info.client.preferred_ciphers = set([])
        self.info.client.sessions_established = 0
        self.info.client.heartbeat = None
        self.info.client.extensions = set([])
        self.info.server = namedtuple("server",
                                      ['versions',
                                       'ciphers',
                                       'compressions',
                                       'sessions_established',
                                       'fallback_scsv',
                                       'heartbeat',
                                       'extensions'])
        self.info.server.versions = set([])
        self.info.server.ciphers = set([])
        self.info.server.compressions = set([])
        self.info.server.sessions_established = 0
        self.info.server.fallback_scsv = None
        self.info.server.heartbeat = None
        self.info.server.certificates = set([])
        self.info.server.extensions = set([])

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

        server.certificates: %s
>
        """ % (len(self.history),
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
               self.info.server.heartbeat,
               repr(self.info.server.certificates))

    def get_events(self):
        events = []
        events.extend(self.events)
        for tlsinfo in (self.info.client, self.info.server):
            # test CRIME - compressions offered?
            tmp = tlsinfo.compressions.copy()
            if 0 in tmp:
                tmp.remove(0)
            if len(tmp):
                events.append(("CRIME - %s supports compression" % tlsinfo.__name__, tlsinfo.compressions))
            # test RC4
            cipher_namelist = [
                TLS_CIPHER_SUITES.get(
                    c, "SSLv2_%s" %
                    SSLv2_CIPHER_SUITES.get(
                        c, c)) for c in tlsinfo.ciphers]

            tmp = [
                c for c in cipher_namelist if isinstance(
                    c,
                    basestring) and "SSLV2" in c.upper() and "EXP" in c.upper()]
            if tmp:
                events.append(("DROWN - SSLv2 with EXPORT ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, basestring) and "EXP" in c.upper()]
            if tmp:
                events.append(("CIPHERS - Export ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, basestring) and "RC4" in c.upper()]
            if tmp:
                events.append(("CIPHERS - RC4 ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, basestring) and "MD2" in c.upper()]
            if tmp:
                events.append(("CIPHERS - MD2 ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, basestring) and "MD4" in c.upper()]
            if tmp:
                events.append(("CIPHERS - MD4 ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, basestring) and "MD5" in c.upper()]
            if tmp:
                events.append(("CIPHERS - MD5 ciphers enabled", tmp))

            tmp = [c for c in cipher_namelist if isinstance(c, basestring) and "RSA_EXP" in c.upper()]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                events.append(("FREAK - server supports RSA_EXPORT cipher suites", tmp))
            tmp = [
                c for c in cipher_namelist if isinstance(
                    c,
                    basestring) and "DHE_" in c.upper() and "EXPORT_" in c.upper()]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                events.append(("LOGJAM - server supports weak DH-Group (512) (DHE_*_EXPORT) cipher suites", tmp))

            exts = [ext for ext in tlsinfo.extensions if ext.haslayer(TLSExtSignatureAlgorithms)]
            # obvious SLOTH check, does not detect impl. errors that allow md5 even though not announced.
            # makes only sense for client_hello
            for ext in exts:
                for alg in ext.algs:
                    if alg in (TLSSignatureScheme.RSA_MD5, TLSSignatureScheme.RSA_PKCS1_SHA1, TLSSignatureScheme.ECDSA_MD5,
                               TLSSignatureScheme.ECDSA_SECP256R1_SHA256, TLSSignatureScheme.DSA_MD5, TLSSignatureScheme.DSA_SHA1):
                        events.append(
                            ("SLOTH - %s announces capability of signature/hash algorithm: %s" %
                             (tlsinfo.__name__, TLS_SIGNATURE_SCHEMES.get(alg)), TLS_SIGNATURE_SCHEMES.get(alg)))

            try:
                for certlist in tlsinfo.certificates:
                    for cert in certlist.certificates:
                        keystore = tlsk.RSAKeystore.from_der_certificate(str(cert.data))
                        pubkey = keystore.public
                        pubkey_size = pubkey.size_in_bits()
                        if pubkey_size < 2048:
                            events.append(
                                ("INSUFFICIENT SERVER CERT PUBKEY SIZE - 2048 >= %d bits" %
                                 pubkey_size, cert))
                        if pubkey_size % 2048 != 0:
                            events.append(
                                ("SUSPICIOUS SERVER CERT PUBKEY SIZE - %d not a multiple of 2048 bits" %
                                 pubkey_size, cert))
                        if pubkey.n in self.RSA_MODULI_KNOWN_FACTORED:
                            events.append(
                                ("SERVER CERT PUBKEY FACTORED - trivial private_key recovery possible due to known factors n = p x q. See https://en.wikipedia.org/wiki/RSA_numbers | grep %s" %
                                 pubkey.n,
                                 cert))
            except AttributeError:
                pass        # tlsinfo.client has no attribute certificates

            if TLSVersion.SSL_2_0 in tlsinfo.versions:
                events.append(("PROTOCOL VERSION - SSLv2 supported ", tlsinfo.versions))

            if TLSVersion.SSL_3_0 in tlsinfo.versions:
                events.append(("PROTOCOL VERSION - SSLv3 supported ", tlsinfo.versions))

            if TLSHeartbeatMode.PEER_ALLOWED_TO_SEND == tlsinfo.heartbeat:
                events.append(("HEARTBEAT - enabled (non conclusive heartbleed) ", tlsinfo.versions))

        if self.info.server.fallback_scsv:
            events.append(
                ("DOWNGRADE / POODLE - FALLBACK_SCSV honored (alert.inappropriate_fallback seen)",
                 self.info.server.fallback_scsv))

        return events

    def insert(self, pkt, client=None):
        self._process(pkt, client=client)

    def _process(self, pkt, client=None):
        if pkt is None:
            return
        if not pkt.haslayer(SSL) and not (pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record)):
            return

        if pkt.haslayer(SSL):
            records = pkt[SSL].records
        else:
            records = [pkt]

        for record in records:
            if client or record.haslayer(TLSClientHello) or record.haslayer(SSLv2ClientHello):
                tlsinfo = self.info.client
            elif not client or record.haslayer(TLSServerHello) or record.haslayer(SSLv2ServerHello):
                tlsinfo = self.info.server

            if not pkt.haslayer(TLSAlert) and pkt.haslayer(TLSRecord):
                tlsinfo.versions.add(pkt[TLSRecord].version)
            elif not pkt.haslayer(TLSAlert) and pkt.haslayer(SSLv2Record):
                tlsinfo.versions.add(TLSVersion.SSL_2_0)

            if record.haslayer(TLSClientHello):
                tlsinfo.ciphers.update(record[TLSClientHello].cipher_suites)
                tlsinfo.compressions.update(record[TLSClientHello].compression_methods)
                if record[TLSClientHello].cipher_suites:
                    tlsinfo.preferred_ciphers.add(pkt[TLSClientHello].cipher_suites[0])
                tlsinfo.extensions.update(record[TLSClientHello].extensions)
            elif record.haslayer(SSLv2ClientHello):
                tlsinfo.ciphers.add(record[SSLv2ClientHello].cipher_suites)

            if record.haslayer(TLSServerHello):
                tlsinfo.ciphers.add(record[TLSServerHello].cipher_suite)
                tlsinfo.compressions.add(record[TLSServerHello].compression_method)
                if record.haslayer(TLSExtHeartbeat):
                    tlsinfo.heartbeat = record[TLSExtHeartbeat].mode
                tlsinfo.extensions.update(record[TLSServerHello].extensions)
            elif record.haslayer(SSLv2ServerHello):
                tlsinfo.ciphers.update(record[SSLv2ServerHello].cipher_suites)

            if record.haslayer(TLSCertificateList):
                tlsinfo.certificates.add(record[TLSCertificateList])

            if record.haslayer(TLSFinished):
                tlsinfo.session.established += 1
            if record.haslayer(TLSHandshake):
                tlsinfo.versions.add(pkt[TLSRecord].version)
            elif record.haslayer(SSLv2ServerHello):
                tlsinfo.versions.add(pkt[SSLv2Record].version)

            if not client and record.haslayer(
                    TLSAlert) and record[TLSAlert].description == TLSAlertDescription.INAPPROPRIATE_FALLBACK:
                tlsinfo.fallback_scsv = True
            # track packet
            self.history.append(pkt)


class TLSScanner(object):

    def __init__(self, workers=10):
        self.workers = workers
        self.capabilities = TLSInfo()

    def scan(self, target, starttls=None):
        for scan_method in (f for f in dir(self) if f.startswith("_scan_")):
            print ("=> %s" % (scan_method.replace("_scan_", "")))
            getattr(self, scan_method)(target, starttls=starttls)

    def sniff(self, target=None, iface=None):
        def _process(pkt):
            match_ip = pkt.haslayer(IP) and (pkt[IP].src == target[0] or pkt[IP].dst == target[0]) if target else True
            match_port = pkt.haslayer(TCP) and (
                pkt[TCP].sport == target[1] or pkt[TCP].dport == target[1]) if len(target) == 2 else True
            if match_ip and match_port:
                self.capabilities.insert(pkt, client=False)
                events = self.capabilities.get_events()         # misuse get_events :/
                if events:
                    strconn = {'src': None,
                               'dst': None,
                               'sport': None,
                               'dport': None}

                    if pkt.haslayer(IP):
                        strconn['src'] = pkt[IP].src
                        strconn['dst'] = pkt[IP].dst
                    if pkt.haslayer(TCP):
                        strconn['sport'] = pkt[TCP].sport
                        strconn['dport'] = pkt[TCP].dport

                    print ("Connection: %(src)s:%(sport)d <==> %(dst)s:%(dport)d" % strconn)
                    print ("* EVENT - " + "\n* EVENT - ".join(e[0] for e in events))
            return
        if iface:
            conf.iface = iface
        while True:
            bpf = None
            if len(target):
                bpf = "host %s" % target[0]
            if len(target) == 2:
                bpf += " and tcp port %d" % target[1]
            sniff(filter=bpf,
                  prn=_process,
                  store=0,
                  timeout=3)

    def _scan_poodle2(self, target, starttls=None, version=TLSVersion.TLS_1_0):
        """taken from poodle2_padding_check"""
        def modify_padding(crypto_container):
            padding = crypto_container.padding
            crypto_container.padding = "\xff%s" % padding[1:]
            return crypto_container

        try:
            t = TCPConnection(target, starttls=starttls)
            ts = TLSSocket(t._s, client=True)
            tls_do_handshake(ts, version, TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA)
            ts.pre_encrypt_hook = modify_padding
            ts.sendall(
                    TLSPlaintext(
                        data="GET / HTTP/1.1\r\nHOST: %s\r\n\r\n" %
                        target[0]),)
            r = ts.recvall()
            if len(r.records) == 0:
                self.capabilities.events.append(
                    ("Poodle2 - not vulnerable, but implementation does not send a BAD_RECORD_MAC alert", r))
            elif r.haslayer(TLSAlert) and r[TLSAlert].description == TLSAlertDescription.BAD_RECORD_MAC:
                # not vulnerable
                pass
            else:
                self.capabilities.events.append(("Poodle2 - vulnerable", r))

        except (socket.error, NotImplementedError) as se:
            print (repr(se))
            return None

    def _scan_compressions(self, target, starttls=None, compression_list=TLS_COMPRESSION_METHODS.keys()):
        for comp in compression_list:
            # prepare pkt
            pkt = TLSRecord() / \
                  TLSHandshakes(handshakes=[TLSHandshake() /
                                            TLSClientHello(version=TLSVersion.TLS_1_1,
                                                           cipher_suites=range(0xfe)[::-1],
                                                           compression_methods=comp)])
            # connect
            try:
                t = TCPConnection(target, starttls=starttls)
                t.sendall(pkt)
                resp = t.recvall(timeout=0.5)
                self.capabilities.insert(resp, client=False)
            except socket.error as se:
                print (repr(se))

    def _check_cipher(self, target, cipher_id, starttls=None, version=TLSVersion.TLS_1_0):
        pkt = TLSRecord(version=version) / \
              TLSHandshakes(handshakes=[TLSHandshake() /
                                        TLSClientHello(version=version,
                                                       cipher_suites=[cipher_id])])
        try:
            t = TCPConnection(target, starttls=starttls)
            t.sendall(pkt)
            resp = t.recvall(timeout=0.5)
        except socket.error as se:
            print (repr(se))
            return None
        return resp

    def _scan_accepted_ciphersuites(
            self,
            target,
            starttls=None,
            cipherlist=TLS_CIPHER_SUITES.keys(),
            version=TLSVersion.TLS_1_0):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            tasks = [
                executor.submit(
                    self._check_cipher,
                    target,
                    cipher_id,
                    starttls,
                    version) for cipher_id in cipherlist]
            for future in concurrent.futures.as_completed(tasks):
                self.capabilities.insert(future.result(), client=False)

    def _scan_supported_protocol_versions(
        self,
        target,
        starttls=None,
        versionlist=(
            (k,
             v) for k,
            v in TLS_VERSIONS.iteritems() if v.startswith("TLS_") or v.startswith("SSL_"))):
        for magic, name in versionlist:
            pkt = TLSRecord(version=magic) / \
                  TLSHandshakes(handshakes=[TLSHandshake() /
                                            TLSClientHello(version=magic,
                                                           cipher_suites=range(0xfe)[::-1],
                                                           extensions=[TLSExtension() /
                                                                       TLSExtHeartbeat(mode=TLSHeartbeatMode.PEER_ALLOWED_TO_SEND)])])
            try:
                # connect
                t = TCPConnection(target, starttls=starttls)
                t.sendall(pkt)
                resp = t.recvall(timeout=0.5)
                self.capabilities.insert(resp, client=False)
            except socket.error as se:
                print (repr(se))

    def _check_cipher_sslv2(self, target, cipher_id, starttls=None, version=TLSVersion.SSL_2_0):
        pkt = SSLv2Record() / SSLv2ClientHello(cipher_suites=[cipher_id], challenge='A' * 16, session_id='')
        try:
            t = TCPConnection(target, starttls=starttls)
            t.sendall(pkt)
            resp = t.recvall(timeout=0.5)
        except socket.error as se:
            print (repr(se))
            return None
        return resp

    def _scan_accepted_ciphersuites_ssl2(
            self,
            target,
            starttls=None,
            cipherlist=SSLv2_CIPHER_SUITES.keys(),
            version=TLSVersion.SSL_2_0):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            tasks = [
                executor.submit(
                    self._check_cipher_sslv2,
                    target,
                    cipher_id,
                    starttls,
                    version) for cipher_id in cipherlist]
            for future in concurrent.futures.as_completed(tasks):
                self.capabilities.insert(future.result(), client=False)

    def _scan_scsv(self, target, starttls=None):
        pkt = TLSRecord(version=TLSVersion.TLS_1_1) / \
              TLSHandshakes(handshakes=[TLSHandshake() /
                                        TLSClientHello(version=TLSVersion.TLS_1_0,
                                                       cipher_suites=[TLSCipherSuite.FALLBACK_SCSV] + range(0xfe)[::-1])])
        # connect
        try:
            t = TCPConnection(target, starttls=starttls)
            t.sendall(pkt)
            resp = t.recvall(timeout=2)
            self.capabilities.insert(resp, client=False)
            if not (resp.haslayer(TLSAlert) and resp[TLSAlert].description ==
                    TLSAlertDescription.INAPPROPRIATE_FALLBACK):
                self.capabilities.events.append(("DOWNGRADE / POODLE - FALLBACK_SCSV - not honored", resp))
        except socket.error as se:
            print (repr(se))

    def _scan_heartbleed(self, target, starttls=None, version=TLSVersion.TLS_1_0, payload_length=20):
        try:
            t = TCPConnection(target, starttls=starttls)
            pkt = TLSRecord(version=version) / TLSHandshakes(handshakes=[TLSHandshake() /
                                                                         TLSClientHello(version=version)])
            t.sendall(pkt)
            resp = t.recvall(timeout=0.5)
            pkt = TLSRecord(version=version) / TLSHeartBeat(length=2**14 - 1, data='bleed...')
            t.sendall(str(pkt))
            resp = t.recvall(timeout=0.5)
            if resp.haslayer(TLSHeartBeat) and resp[TLSHeartBeat].length > 8:
                self.capabilities.events.append(("HEARTBLEED - vulnerable", resp))
        except socket.error as se:
            print (repr(se))
            return None
        return resp

    def _scan_secure_renegotiation(self, target, starttls=None, version=TLSVersion.TLS_1_0, payload_length=20):
        # todo: also test EMPTY_RENEGOTIATION_INFO_SCSV
        try:
            t = TCPConnection(target, starttls=starttls)
            pkt = TLSRecord(version=version) / \
                  TLSHandshakes(handshakes=[TLSHandshake() /
                                            TLSClientHello(version=version,
                                                           extensions=TLSExtension() /
                                                                      TLSExtRenegotiationInfo())])
            t.sendall(pkt)
            resp = t.recvall(timeout=0.5)
            if resp.haslayer(TLSExtRenegotiationInfo):
                self.capabilities.events.append(("TLS EXTENSION SECURE RENEGOTIATION - not supported", resp))
        except socket.error as se:
            print (repr(se))
            return None
        return resp


def main():
    print (__doc__)
    if len(sys.argv) <= 3:
        print ("USAGE: <mode> <host> <port> [starttls] [num_worker] [interface]")
        print ("       mode     ... client | sniff")
        print ("       starttls ... starttls keyword e.g. 'starttls\\n' or 'ssl\\n'")
        print ("available interfaces")
        for i in get_if_list():
            print ("   * %s" % i)
        exit(1)
    mode = sys.argv[1]
    starttls = sys.argv[4] if len(sys.argv) > 4 else None
    host = sys.argv[2]
    port = int(sys.argv[3])
    num_workers = 10 if not len(sys.argv) > 5 else int(sys.argv[5])
    iface = "eth0" if not len(sys.argv) > 6 else sys.argv[6]

    scanner = TLSScanner(workers=num_workers)
    if mode == "sniff":
        print ("[*] [passive] Scanning in 'sniff' mode for %s on %s..." % (repr((host, port)), iface))
        scanner.sniff((host, port), iface=iface)
    else:
        print ("[*] [active] Scanning with %s parallel threads..." % num_workers)
        t_start = time.time()
        scanner.scan((host, port), starttls=starttls)
        print ("\n")
        print ("[*] Capabilities (Debug)")
        print (scanner.capabilities)
        print ("[*] supported ciphers: %s/%s" % (
            len(scanner.capabilities.info.server.ciphers), len(TLS_CIPHER_SUITES) + len(SSLv2_CIPHER_SUITES)))
        print (" * " + "\n * ".join(
            ("%s (0x%0.4x)" % (TLS_CIPHER_SUITES.get(c, "SSLv2_%s" % SSLv2_CIPHER_SUITES.get(c, c)), c) for c in
             scanner.capabilities.info.server.ciphers)))
        print ("")
        print (
            "[*] supported protocol versions: %s/%s" %
            (len(
                scanner.capabilities.info.server.versions),
                len(TLS_VERSIONS)))
        print (" * " + "\n * ".join(
            ("%s (0x%0.4x)" % (TLS_VERSIONS.get(c, c), c) for c in scanner.capabilities.info.server.versions)))
        print ("")
        print ("[*] supported compressions methods: %s/%s" % (
            len(scanner.capabilities.info.server.compressions), len(TLS_COMPRESSION_METHODS)))
        print (" * " + "\n * ".join(("%s (0x%0.4x)" % (TLS_COMPRESSION_METHODS.get(c, c), c) for c in
                                     scanner.capabilities.info.server.compressions)))
        print ("")
        events = scanner.capabilities.get_events()
        print ("[*] Events: %s" % len(events))
        print ("* EVENT - " + "\n* EVENT - ".join(e[0] for e in events))
        t_diff = time.time() - t_start
        print ("")
        print ("Scan took: %ss" % t_diff)


if __name__ == "__main__":
    main()
