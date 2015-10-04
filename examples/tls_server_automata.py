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
    from scapy_ssl_tls.ssl_tls_automata import TLSServerAutomata
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls_automata import TLSServerAutomata
    from scapy.layers.ssl_tls import *


if __name__=='__main__':
    log_interactive.setLevel(1)
 
    if len(sys.argv)>2:
        target = (sys.argv[1],int(sys.argv[2]))
    else:
        target = ("127.0.0.1", 8443)
 
    TLSServerAutomata.graph()
    auto_srv = TLSServerAutomata(debug=9,
                             target=target,
                             tls_version="TLS_1_1",
                             cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                             response="HTTP/1.1 200 OK\r\n\r\n")
    print auto_srv.run()
