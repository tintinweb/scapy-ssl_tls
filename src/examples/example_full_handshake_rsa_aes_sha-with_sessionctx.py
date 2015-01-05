#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

def sendrcv(sock, p, bufflen=1024):
    sock.settimeout(5)
    print "sending TLS payload"
    sock.sendall(p)
    resp=''
    try:
        while 1:
            t = sock.recv(1)
            if not(len(t)):
                break
            resp += t
    except:
        print "timeout"
        
        
    #print "received, %d --  %s"%(len(resp),repr(resp))
    return resp

if __name__=="__main__":
    import scapy
    from scapy.all import *    
    import socket
    #<----- for local testing only
    sys.path.append("../scapy/layers")
    from ssl_tls import *
    import ssl_tls_crypto
    from Crypto.Cipher import PKCS1_v1_5
    #------>
    target = ('192.168.220.131',4433)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    print "* connecting ..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    # feed privatekey for ssl decryption and master_secret regeneration
    print "* init TLSSessionContext"
    session = ssl_tls_crypto.TLSSessionCtx()
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
    session.rsa_load_privkey(privkey)
    
    # create TLS Handshake / Client Hello packet
    print "* -> client hello"
    p = TLSRecord()/TLSHandshake()/TLSClientHello(compression_methods=None, 
                                                  cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA],
                                                  random_bytes='R'*28)
          
        
    #p.show()
    sp=str(p)
    session.insert(SSL(sp))     # track in sessionctx
    r = sendrcv(s,sp)
    #SSL(r).show()
    session.insert(SSL(r))      # track response in sessionctx
    print "* <- server hello"
    # send premaster secret
    client_hello = p
    server_hello = SSL(r)  

    #generate random premaster secret
    secparams = ssl_tls_crypto.TLSSecurityParameters()
    # latest_version + 46rndbytes
    secparams.premaster_secret = '\03\01'+'a'*22+'b'*24
    secparams.generate(secparams.premaster_secret, 
                       struct.pack("!I",client_hello[TLSClientHello].gmt_unix_time)+client_hello[TLSClientHello].random_bytes,
                       struct.pack("!I",server_hello[TLSServerHello].gmt_unix_time)+server_hello[TLSServerHello].random_bytes)
    
    print "* chose premaster_secret and generate master_secret + key material"
    print "** chosen premaster_secret", repr(secparams.premaster_secret)
    print "** generated master_secret", repr(secparams.master_secret)    
    # encrypt pms with server pubkey from first cert
    #extract server cert (first one counts)
    print "* fetch servers RSA pubkey"
    cert = SSL(r)[TLSCertificateList].certificates[0].data
    pubkey = ssl_tls_crypto.x509_extract_pubkey_from_der(cert)
    
    # PKCS1 padd encrypt with pubkey
    
    print "* encrypt premaster_secret with servers RSA pubkey"
    pkcs1_pubkey = PKCS1_v1_5.new(pubkey)
    enc= pkcs1_pubkey.encrypt(secparams.premaster_secret)
    pms = ''.join(enc)

    print "* -> TLSClientKeyExchange with EncryptedPremasterSecret"
    p = TLSRecord()/TLSHandshake()/TLSClientKeyExchange()/TLSKexParamEncryptedPremasterSecret(data=pms)
    #p.show2()
    sp = str(p)
    session.insert(SSL(sp))
    r = sendrcv(s,sp)
    #SSL(r).show()
    # change cipherspec
    print "* -> ChangeCipherSpec"
    p = TLSRecord()/TLSChangeCipherSpec()
    #p.show2()
    
    r = sendrcv(s,str(p))
    #SSL(r).show()
    print "* FIXME: implement TLSFinished ..."
    print "* SSL Session parameter and keys: "
    print repr(session)
    print "* you should now be able to encrypt/decrypt any client/server communication for this session :)"
    s.close()
    
    