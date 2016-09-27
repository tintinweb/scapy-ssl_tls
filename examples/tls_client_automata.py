#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

import os
import sys

from scapy.all import conf, log_interactive

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls_automata import TLSClientAutomata
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls_automata import TLSClientAutomata
    from scapy.layers.ssl_tls import *



if __name__=='__main__':
    log_interactive.setLevel(1)

    if len(sys.argv)>2:
        target = (sys.argv[1],int(sys.argv[2]))
    else:
        target = ("127.0.0.1", 8443)

    TLSClientAutomata.graph()

    auto_cli = TLSClientAutomata(debug=10,
                             target=target,
                             tls_version="TLS_1_1",
                             cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                                            TLSCipherSuite.RSA_WITH_RC4_128_SHA,
                                            TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA,
                                            TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA],
                             request="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n")

    print ( auto_cli.run())
