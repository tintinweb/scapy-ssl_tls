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
        
    server_pem = sys.argv[3] if len(sys.argv)>3 else "../tests/files/openssl_1_0_1_f_server.pem"
 
    TLSServerAutomata.graph()
    print "using certificate/keyfile: %s"%server_pem
    with open(server_pem,'r') as f:
        pemcert = f.read()
    auto_srv = TLSServerAutomata(debug=9,
                             bind=target,
                             pemcert=pemcert,
                             cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                             response="HTTP/1.1 200 OK\r\n\r\n")
    
    def jump_to_server_hello_done(*args, **kwargs):
        raw_input(" **** -------------> override state, directly jump to SERVER_CERTIFICATES_SENT aka. SERVER_HELLO_DONE")
        raise auto_srv.SERVER_CERTIFICATES_SENT()
    
    # uncomment next line to hook into the 'send_server_hello' condition.  
    # auto_srv.register_callback('send_server_hello', jump_to_server_hello_done)
    print auto_srv.run()
