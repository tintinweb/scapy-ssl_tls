#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import sys, os
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
    import scapy_ssl_tls.ssl_tls_crypto as ssl_tls_crypto
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    import scapy.layers.ssl_tls_crypto as ssl_tls_crypto
    
import socket

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
        
        
    print "received, %d --  %s"%(len(resp),repr(resp))
    return resp

if __name__=="__main__":
    history = []
    target = ('www.remote.host',443)            # MAKE SURE TO CHANGE THIS
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    session = ssl_tls_crypto.TLSSessionCtx()
    session.rsa_load_privkey(open('c:\\_tmp\\polarssl.key','r').read())
    
    
    # fake initial session packet for session tracking
    sip,sport= s.getsockname()
    session.insert(IP(src=sip,dst=target[0])/TCP(sport=sport,dport=target[1]))
    
    # create TLS Handhsake / Client Hello packet
    p = TLSRecord()/TLSHandshake()/TLSClientHello(compression_methods=None, 
                                                  cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA],
                                                  random_bytes='R'*28)
          
        
    p.show()
    sp =str(p)

    session.insert(SSL(sp))
    history.append(SSL(sp))
    r = sendrcv(s,sp)
    SSL(r).show()
    history.append(SSL(r))
    session.insert(SSL(r))
    
    # send premaster secret
    #p = TLSRecord()/TLSHandshake()/TLSClientKeyExchange()/TLSKexParamDH("haha")
    client_hello = p
    server_hello = SSL(r)  

    #generate random premaster secret
    secparams = ssl_tls_crypto.TLSSecurityParameters()
    # latest_version + 46rndbytes
    secparams.premaster_secret = '\03\01'+'a'*22+'b'*24
    print "client_random:",repr(struct.pack("!I",client_hello[TLSClientHello].gmt_unix_time)+client_hello[TLSClientHello].random_bytes)
    print "server_random:",repr(struct.pack("!I",server_hello[TLSServerHello].gmt_unix_time)+server_hello[TLSServerHello].random_bytes)
    
    
    secparams.generate(secparams.premaster_secret, 
                       struct.pack("!I",client_hello[TLSClientHello].gmt_unix_time)+client_hello[TLSClientHello].random_bytes,
                       struct.pack("!I",server_hello[TLSServerHello].gmt_unix_time)+server_hello[TLSServerHello].random_bytes)
    
    print "master", repr(secparams.master_secret)    

    # encrypt pms with server pubkey from first cert
    #extract server cert (first one counts)
    cert = SSL(r)[TLSCertificateList].certificates[0].data
    pubkey = ssl_tls_crypto.x509_extract_pubkey_from_der(cert)
    
    
    
    print repr(pubkey.exportKey(format="DER"))
    #print pubkey
    print pubkey.can_encrypt()
    print pubkey.can_sign()
    print pubkey.publickey()
    print repr(secparams.premaster_secret)
    
    # PKCS1 padd encrypt with pubkey
    from Crypto.Cipher import PKCS1_OAEP,PKCS1_v1_5
    
    pkcs1_pubkey = PKCS1_v1_5.new(pubkey)
    enc= pkcs1_pubkey.encrypt(secparams.premaster_secret)
    print repr(enc)
   
   
    print "---------------"
    # manually check by decrypting the encrypted text with the privkey
    with open('c:\\_tmp\\polarssl.key','r') as f:
        key = RSA.importKey(f.read())
        pkcs1_key = PKCS1_v1_5.new(key)
    print "decrypted pms=",repr(pkcs1_key.decrypt(enc,None))
    print "---------------"
    pms = ''.join(enc)
    print "PMS(pkcs1)==",len(pms),repr(pms)

    
    p = TLSRecord()/TLSHandshake()/TLSClientKeyExchange()/TLSKexParamEncryptedPremasterSecret(data=pms)
    #p.show2()
    sp = str(p)
    history.append(SSL(sp))
    session.insert(SSL(sp))
    r = sendrcv(s,sp)
    #SSL(r).show()
    #history.append(SSL(r))
    # change cipherspec
    p = TLSRecord()/TLSChangeCipherSpec()
    #p.show2()
    
    r = sendrcv(s,str(p))
    #SSL(r).show()
    print repr(session)
    exit() 

    print secparams
    # send encrypted finish with hash of previous msgs
    from Crypto.Hash import MD5,SHA
    
    hs_msgs = ''
    for  p in history:
        for r in p.records:
            print r[TLSHandshake].payload.show()
            hs_msgs += str(r[TLSHandshake].payload)
    
    print "hs_mgs_hashed:",repr(MD5.new(hs_msgs).digest()+SHA.new(hs_msgs).digest())
    msg_hash= secparams.prf.prf_numbytes(secparams.master_secret,
                                         secparams.prf.TLS_MD_CLIENT_FINISH_CONST,
                                         MD5.new(hs_msgs).digest()+SHA.new(hs_msgs).digest(),
                                         numbytes=12)
    
    # TODO: incomplete
    
    print repr(msg_hash)
    
    p = TLSRecord()/TLSCiphertext().encrypt(TLSPlaintext().compress(str(TLSHandshake()/TLSFinished(data=msg_hash))))
    #p = TLSRecord()/TLSHandshake()/TLSFinished(data=msg_hash)
    r = sendrcv(s,str(p))
    #SSL(r).show()
    
    s.close()