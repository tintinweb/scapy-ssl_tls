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
    
    
    target = ('192.168.220.131',4433)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord()/ \
        TLSHandshake()/ \
        TLSClientHello(compression_methods=range(0xff), 
                       cipher_suites=range(0xff), 
                       extensions=[TLSExtension()/ \
                                  TLSALPN(protocol_name_list= \
                                                    [TLSALPNProtocol(data="http/1.1"),
                                                     TLSALPNProtocol(data="http/1.3"),
                                                     TLSALPNProtocol(data="\x00htt\x01%sp/1.1"),
                                                     ])],)
                
    p.show()

    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(1024)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    
    
    s.close()
    
    