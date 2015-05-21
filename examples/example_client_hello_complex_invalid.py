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
    
    
    target = ('www.remote.host',443)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord(version='TLS_1_2')/ \
            TLSHandshake()/ \
                TLSClientHello(compression_methods= [TLSCompressionMethod.NULL,TLSCompressionMethod.DEFLATE]+range(255-2),
                               cipher_suites= [TLSCipherSuite.NULL_WITH_NULL_NULL]+range(0xff-1),
                               extensions=[
                                       TLSExtension()/ \
                                            TLSServerNameIndication(server_names= [TLSServerName(data="a"*500,length=16),
                                                                                   TLSServerName(length=222)]),
                                       TLSExtension()/ \
                                            TLSServerNameIndication(server_names=[TLSServerName(length=2)])
                                       ])
                
    p.show()

    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(1024)
    print "received, %s"%repr(resp)
    
    SSL(resp).show()
    
    s.close()
    
    