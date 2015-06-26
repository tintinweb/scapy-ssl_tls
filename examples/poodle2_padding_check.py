#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import socket
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *

def modify_padding(crypto_container):
    padding = crypto_container.padding
    crypto_container.padding = "\xff%s" % padding[1:]
    return crypto_container

def poodle2_test(server):
    s = socket.socket()
    s.connect(server)
    ts = TLSSocket(s, client=True)
    version = TLSVersion.TLS_1_0
    tls_do_handshake(ts, version, TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA)
    ts.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: %s\r\n\r\n" % server[0]), ts.tls_ctx, pre_encrypt_hook=modify_padding))
    r = ts.recvall()
    if len(r.records) == 0:
        print("Server is not vulnerable to poodle 2, but implementation does not send a BAD_RECORD_MAC alert")
    elif r.haslayer(TLSAlert) and r[TLSAlert].description == TLSAlertDescription.BAD_RECORD_MAC:
        print("Server is not vulnerable to poodle 2")
    else:
        print("Server is probably vulnerable to poodle 2")
        print("If following packet displays application data, server is definitely vulnerable to poodle 2")
        r.show()

if __name__ == "__main__":
    if len(sys.argv)>2:
        server = (sys.argv[1],int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    poodle2_test(server)