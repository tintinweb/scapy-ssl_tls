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
    
    # create SSLv2 Handhsake / Client Hello packet
    p = SSLv2Record()/SSLv2ClientHello(cipher_suites=SSL2_CIPHER_SUITES.keys(),challenge='a'*16,session_id='a'*16)           
    p.show()

    SSL(str(p)).show()
    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(8*1024)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    
    
    s.close()
    
    