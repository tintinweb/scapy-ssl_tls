#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>


if __name__=="__main__":
    import scapy
    from scapy.all import *
    import socket
    #<----- for local testing only
    sys.path.append("../scapy/layers")
    from ssl_tls import *
    #------>

    print "connecting.."
    target = ('www.remote.host',443)            # MAKE SURE TO CHANGE THIS
    print "connected."
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord(version="SSL_3_0")/TLSHandshake()/TLSClientHello(version="SSL_3_0",compression_methods=range(0xff), cipher_suites=range(0xff))
                
    p.show()

    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(10240)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(10240)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    
    
    
    
    
    
    s.close()
    
    