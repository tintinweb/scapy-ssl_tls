#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

from __future__ import print_function
import sys
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

import socket

if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print ("USAGE: <host> <port>")
        exit(1)

    target = (sys.argv[1], int(sys.argv[2]))
    # create tcp socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(target)

    # create TLS Handhsake / Client Hello packet
    p = TLSRecord() / TLSHandshakes(handshakes=[TLSHandshake() /
                                                TLSClientHello(cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])])

    p.show()
    print ("sending TLS payload")
    s.sendall(str(p))
    resp = s.recv(1024 * 8)
    print ("received, %d --  %s" % (len(resp), repr(resp)))
    SSL(resp).show()
    s.close()
