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
import itertools

# https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00
if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print ("USAGE: <host> <port>")
        exit(1)

    target = (sys.argv[1], int(sys.argv[2]))

    PROTOS = [p for p in TLS_VERSIONS.values() if p.startswith("TLS_") or p.startswith("SSL_3")]

    TESTS = itertools.product(PROTOS, repeat=2)
    RESULTS = []

    TLS_FALLBACK_SCSV_SUPPORTED = False
    SSLV3_ENABLED = True

    for t in TESTS:
        print ("----------------")
        print ("TEST : %s" % repr(t))
        print ("----------------")
        print ("connecting..")

        # create tcp socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(target)
        print ("connected.")
        # create TLS Handshake / Client Hello packet
        outer, inner = t
        p = TLSRecord(version=outer) / \
            TLSHandshakes(handshakes=[TLSHandshake() /
                                      TLSClientHello(version=inner,
                                                     compression_methods=range(0xff),
                                                     cipher_suites=range(0xff) + [0x5600],)])
        p.show()
        print ("sending TLS payload")
        s.sendall(str(p))
        resp = s.recv(10240)
        s.close()
        print ("received, %s" % repr(resp))
        resp = SSL(resp)
        resp.show()

        if resp.haslayer(TLSAlert):
            v = resp[TLSRecord].version
            if resp[TLSAlert].description == 86:        # INAPPROPRIATE_FALLBACK
                print ("[* ] SUCCESS - server honors TLS_FALLBACK_SCSV")
                RESULTS.append((t, "resp: TLSAlert.INAPPROPRIATE_FALLBACK  %s" % TLS_VERSIONS.get(v, v)))
                TLS_FALLBACK_SCSV_SUPPORTED = True      # we've caught the SCSV alert
            else:
                print ("[- ] UNKNOWN - server responds with unexpected alert")
                a_descr = resp[TLSAlert].description
                RESULTS.append((t, "resp: TLSAlert.%s" % TLS_ALERT_DESCRIPTIONS.get(a_descr, a_descr)))

        elif resp.haslayer(TLSServerHello):
            print ("[!!] FAILED - server allows downgrade to %s" % t[1])
            v_outer = resp[TLSRecord].version
            v = resp[TLSServerHello].version
            RESULTS.append(
                (t, "resp: TLSServerHello:            outer %s inner %s" %
                 (TLS_VERSIONS.get(
                     v_outer, v_outer), TLS_VERSIONS.get(
                     v, v))))
            if t[1] == "TLS_3_0":
                SSLV3_ENABLED = False
        else:
            print ("[!!] UNKNOWN - unexpected response..")
            RESULTS.append((t, "Unexpected response"))

    print ("-----------------------")
    print ("for: %s" % repr(target))
    print ("   record      hello   ")
    for t, r in RESULTS:
        print ("%s  ... %s" % (t, r))
    print ("overall:")
    print ("    TLS_FALLBACK_SCSV_SUPPORTED   ...  %s" % repr(TLS_FALLBACK_SCSV_SUPPORTED))
    print ("    SSLv3_ENABLED                 ...  %s" % repr(SSLV3_ENABLED))
