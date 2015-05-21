#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>



import scapy
from scapy.all import *    
import socket
#<----- for local testing only
sys.path.append("../scapy/layers")
from ssl_tls import *

import random

def id_generator(size=500, chars=[chr(x) for x in xrange(255)]):
    return ''.join(random.choice(chars) for _ in range(size))

def test_eq(payload):
    p = TLSPlaintext(data=payload)
    #p.show2()
    p = p.compress(TLSCompressionMethod.DEFLATE)
    #p.show2()
    p = p.decompress(TLSCompressionMethod.DEFLATE)
    #p.show2()
    if payload==p.data:
        print "success: :) %s"%(repr(payload))
    else:
        print "failed : !! %s"%(repr(payload))
        raise Exception("Test failed: %s!=%s"%(repr(payload),repr(p.data)))
        
if __name__=="__main__":
    print "--start--"
    for i in xrange(100):
        payload = id_generator(size=random.randint(0,10000))
        
        test_eq(payload)
        
 

    print "--done--"