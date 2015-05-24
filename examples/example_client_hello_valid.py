#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import sys, os
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    
import socket

if __name__=="__main__":
    target = ('www.remote.host',443)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord()/TLSHandshake()/TLSClientHello(compression_methods=range(0xff), cipher_suites=range(0xff))
                
    p.show()

    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(1024)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    
    s.close()