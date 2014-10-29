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
    
    
    target = ('www.google.com',443)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord()/TLSHandshake()/TLSClientHello(compression_methods=None, cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA])
                
    p.show()

    
    print "sending TLS payload"
    s.sendall(str(p))
    resp=''
    for i in range(15):
        resp += s.recv(1024)
    print "received, %d --  %s"%(len(resp),repr(resp))
    SSL(resp).show()
    
    
    s.close()
    
    