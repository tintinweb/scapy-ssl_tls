#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
'''

server:
    #> openssl s_server -accept 443 -WWW -debug -cipher AES128-SHA
client:
    #> openssl s_client -connect 192.168.220.131:443 -tls1

'''

import sys, os
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
    import scapy_ssl_tls.ssl_tls_crypto as ssl_tls_crypto
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    import scapy.layers.ssl_tls_crypto as ssl_tls_crypto
    
import socket

if __name__=="__main__":
    '''
    #fetch interfaces
    for i in get_if_list():
        print i
    conf.iface = "eth14"
    '''
    
    ssl_session_map = {}
    
    def process_ssl(p):
        # force SSL evaluation
        if p.haslayer(SSL):
            # get session for server or client tuple
            session = ssl_session_map.get((p[IP].dst,p[TCP].dport)) or ssl_session_map.get((p[IP].src,p[TCP].sport))
            
            if not session:
                # session not found
                return
            
            if p.haslayer(TLSServerHello):
                session.printed=False
                session.crypto.session.master_secret=None
                #reset the session and print it next time

            for p in p[SSL].records:
                print "processing..",repr(p[TLSRecord])
                session.insert(p)            
                if session.crypto.session.master_secret and session.printed==False:
                    print repr(session)
                    session.printed = True
                
                if p[TLSRecord].content_type==0x17:
                    pp = session.tlsciphertext_decrypt(p,session.crypto.client.dec)
                    pp.show()


    print "* load servers privatekey for auto master-key decryption (RSA key only)"
    #session.rsa_load_privkey(open('polarssl.key','r').read())
    # openssl/apps/server.pem privkey
    privkey="""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA84TzkjbcskbKZnrlKcXzSSgi07n+4N7kOM7uIhzpkTuU0HIv
h4VZS2axxfV6hV3CD9MuKVg2zEhroqK1Js5n4ke230nSP/qiELfCl0R+hzRtbfKL
tFUr1iHeU0uQ6v3q+Tg1K/Tmmg72uxKrhyHDL7z0BriPjhAHJ5XlQsvR1RCMkqzu
D9wjSInJxpMMIgLndOclAKv4D1wQtYU7ZpTw+01XBlUhIiXb86qpYL9NqnnRq5JI
uhmOEuxo2ca63+xaHNhD/udSyc8C0Md/yX6wlONTRFgLLv0pdLUGm1xEjfsydaQ6
qGd7hzIKUI3hohNKJa/mHLElv7SZolPTogK/EQIDAQABAoIBAADq9FwNtuE5IRQn
zGtO4q7Y5uCzZ8GDNYr9RKp+P2cbuWDbvVAecYq2NV9QoIiWJOAYZKklOvekIju3
r0UZLA0PRiIrTg6NrESx3JrjWDK8QNlUO7CPTZ39/K+FrmMkV9lem9yxjJjyC34D
AQB+YRTx+l14HppjdxNwHjAVQpIx/uO2F5xAMuk32+3K+pq9CZUtrofe1q4Agj9R
5s8mSy9pbRo9kW9wl5xdEotz1LivFOEiqPUJTUq5J5PeMKao3vdK726XI4Z455Nm
W2/MA0YV0ug2FYinHcZdvKM6dimH8GLfa3X8xKRfzjGjTiMSwsdjgMa4awY3tEHH
674jhAECgYEA/zqMrc0zsbNk83sjgaYIug5kzEpN4ic020rSZsmQxSCerJTgNhmg
utKSCt0Re09Jt3LqG48msahX8ycqDsHNvlEGPQSbMu9IYeO3Wr3fAm75GEtFWePY
BhM73I7gkRt4s8bUiUepMG/wY45c5tRF23xi8foReHFFe9MDzh8fJFECgYEA9EFX
4qAik1pOJGNei9BMwmx0I0gfVEIgu0tzeVqT45vcxbxr7RkTEaDoAG6PlbWP6D9a
WQNLp4gsgRM90ZXOJ4up5DsAWDluvaF4/omabMA+MJJ5kGZ0gCj5rbZbKqUws7x8
bp+6iBfUPJUbcqNqFmi/08Yt7vrDnMnyMw2A/sECgYEAiiuRMxnuzVm34hQcsbhH
6ymVqf7j0PW2qK0F4H1ocT9qhzWFd+RB3kHWrCjnqODQoI6GbGr/4JepHUpre1ex
4UEN5oSS3G0ru0rC3U4C59dZ5KwDHFm7ffZ1pr52ljfQDUsrjjIMRtuiwNK2OoRa
WSsqiaL+SDzSB+nBmpnAizECgYBdt/y6rerWUx4MhDwwtTnel7JwHyo2MDFS6/5g
n8qC2Lj6/fMDRE22w+CA2esp7EJNQJGv+b27iFpbJEDh+/Lf5YzIT4MwVskQ5bYB
JFcmRxUVmf4e09D7o705U/DjCgMH09iCsbLmqQ38ONIRSHZaJtMDtNTHD1yi+jF+
OT43gQKBgQC/2OHZoko6iRlNOAQ/tMVFNq7fL81GivoQ9F1U0Qr+DH3ZfaH8eIkX
xT0ToMPJUzWAn8pZv0snA0um6SIgvkCuxO84OkANCVbttzXImIsL7pFzfcwV/ERK
UM6j0ZuSMFOCr/lGPAoOQU0fskidGEHi1/kW+suSr28TqsyYZpwBDQ==
-----END RSA PRIVATE KEY-----
"""
    session = ssl_tls_crypto.TLSSessionCtx()
    session.rsa_load_privkey(privkey)
    session.printed=False
    
    ssl_session_map[('192.168.220.131',443)]=session
    
    while True:
        sniff(filter="tcp port 443",prn=process_ssl,store=0,timeout=3)

    s.close()