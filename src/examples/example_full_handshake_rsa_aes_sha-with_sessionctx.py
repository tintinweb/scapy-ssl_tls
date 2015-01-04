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
    session.rsa_load_privkey(open('c:\\_tmp\\polarssl.key','r').read())
    
    # fake initial session packet for session tracking
    # session context autoupdates itself whenever a packet is inserted.
    sip,sport= s.getsockname()
    session.insert(IP(src=sip,dst=target[0])/TCP(sport=sport,dport=target[1]))
    
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
    
    