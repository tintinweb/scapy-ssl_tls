#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>


if __name__=="__main__":
    import scapy
    from scapy.layers.ssl_tls import *
    
    import socket
    
    
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
    
    s.close()
    
    