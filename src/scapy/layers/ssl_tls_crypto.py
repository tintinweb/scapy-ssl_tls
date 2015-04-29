#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html

import hashlib
import Crypto
import ssl_tls as tls
from Crypto.Hash import HMAC, MD5, SHA
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5#,PKCS1_OAEP
from scapy.layers.inet import TCP, UDP, IP
import struct
import pkcs7
import array
from collections import namedtuple
'''
https://tools.ietf.org/html/rfc4346#section-6.3
    key_block = PRF(SecurityParameters.master_secret,
                          "key expansion",
                          SecurityParameters.server_random +
             SecurityParameters.client_random

      client_write_MAC_secret[SecurityParameters.hash_size]
       server_write_MAC_secret[SecurityParameters.hash_size]
       client_write_key[SecurityParameters.key_material_length]
       server_write_key[SecurityParameters.key_material_length]
'''
def prf(master_secret, label, data):
    pass

def x509_extract_pubkey_from_der(der_certificate):
    # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
    cert = DerSequence()
    cert.decode(der_certificate)                
    
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])       # first DER SEQUENCE
    
    # search for pubkey OID: rsaEncryption: "1.2.840.113549.1.1.1"
    # hex: 06 09 2A 86 48 86 F7 0D 01 01 01 
    subjectPublicKeyInfo=None
    for seq in tbsCertificate:
        if not isinstance(seq,basestring): continue     # skip numerics and non sequence stuff
        if "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" in seq:
            subjectPublicKeyInfo=seq
        
    if not subjectPublicKeyInfo:
        raise ValueError("could not find OID rsaEncryption 1.2.840.113549.1.1.1 in certificate")

    # Initialize RSA key
    return RSA.importKey(subjectPublicKeyInfo)

def x509_extract_pubkey_from_pem(public_key_string):
    #https://github.com/m4droid/U-Pasaporte/blob/7a00b344e97bb05265fd726f4125f0966dca6a5a/upasaporte/__init__.py
    # Convert from PEM to DER
    lines = public_key_string.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))

    return x509_extract_pubkey_from_der(der)

def describe_ciphersuite(cipher_id):
    '''
    e.g  int 0x0033 => 'RSA_WITH_AES_128_CBC_SHA'
    '''
    cipher_string = tls.TLS_CIPHER_SUITES.get(cipher_id)
    
    kex, encmac = cipher_string.split("_WITH_")
    kex = kex.split("_")
    encmac =  encmac.split("_")
    enc = encmac[:-1]
    mac = encmac[-1:]
    
    return kex, enc, mac
    

class PKCS7Wrapper(object):
    def __init__(self, cipher_object):
        self.cipher_object=cipher_object
        self.encoder = pkcs7.PKCS7Encoder(k=cipher_object.block_size)       # padd 16
        
    def encrypt(self, plaintext):
        return self.cipher_object.encrypt(self.encoder.encode(plaintext))
    
    def decrypt(self, ciphertext):
        return self.encoder.decode(self.cipher_object.decrypt(ciphertext))

def ciphersuite_factory(cipher_id, key, iv):
    kex, enc, mac = describe_ciphersuite(cipher_id)
    #print kex,enc,mac
    
    if not "AES" in enc:
        raise Exception("Encryption Cipher not supported: %s"%enc)
    
    
    
    if "CBC" in enc:
        mode = AES.MODE_CBC
    else:
        raise Exception("Crypto Mode not supported: %s"%enc)
    
    encryptor = AES.new(key, mode=mode, IV=iv)
    return PKCS7Wrapper(encryptor)


class TLSSessionCtx(object):
    def __init__(self):
        self.packets = namedtuple('packets',['history','client','server'])
        self.packets.history=[]         #packet history
        self.packets.client = namedtuple('client',['sequence'])
        self.packets.client.sequence=0
        self.packets.server = namedtuple('server',['sequence'])
        self.packets.server.sequence=0
        
        self.params = namedtuple('params', ['handshake',
                                            'negotiated',])
        self.params.handshake = namedtuple('handshake',['client','server'])
        self.params.handshake.client=None
        self.params.handshake.server=None
        self.params.negotiated = namedtuple('negotiated', ['ciphersuite',
                                                            'key_exchange',
                                                            'encryption',
                                                            'mac',
                                                            'compression',
                                            ])
        self.params.negotiated.ciphersuite=None
        self.params.negotiated.key_exchange=None
        self.params.negotiated.encryption=None
        self.params.negotiated.mac=None
        self.params.negotiated.compression=None
        self.crypto = namedtuple('crypto', ['client','server'])
        self.crypto.client = namedtuple('client', ['enc','dec'])
        self.crypto.client.enc = None
        self.crypto.client.dec = None
        self.crypto.server = namedtuple('server', ['enc','dec','rsa'])
        self.crypto.server.enc = None
        self.crypto.server.dec = None
        self.crypto.server.rsa = namedtuple('rsa', ['pubkey','privkey'])
        self.crypto.server.rsa.pubkey=None
        self.crypto.server.rsa.privkey=None
        self.crypto.session = namedtuple('session', ['premaster_secret',
                                                     'master_secret'])
        
        self.crypto.session.encrypted_premaster_secret=None
        self.crypto.session.premaster_secret=None
        self.crypto.session.master_secret=None
        self.crypto.session.randombytes = namedtuple('randombytes',['client','server'])
        self.crypto.session.randombytes.client=None
        self.crypto.session.randombytes.server=None
        
        self.crypto.session.key = namedtuple('key',['client','server'])
        self.crypto.session.key.server = namedtuple('server',['mac','encryption','iv'])
        self.crypto.session.key.server.mac = None
        self.crypto.session.key.server.encryption = None
        self.crypto.session.key.server.iv = None

        self.crypto.session.key.client = namedtuple('client',['mac','encryption','iv'])
        self.crypto.session.key.client.mac = None
        self.crypto.session.key.client.encryption = None
        self.crypto.session.key.client.iv = None
        
        self.crypto.session.key.length = namedtuple('length',['mac','encryption','iv'])
        self.crypto.session.key.length.mac = None
        self.crypto.session.key.length.encryption = None
        self.crypto.session.key.length.iv = None

        
        
    def __repr__(self):
        params = {'id':id(self),
                  'params-handshake-client':repr(self.params.handshake.client),
                  'params-handshake-server':repr(self.params.handshake.server),
                  'params-negotiated-ciphersuite':self.params.negotiated.ciphersuite,
                  'params-negotiated-key_exchange':self.params.negotiated.key_exchange,
                  'params-negotiated-encryption':self.params.negotiated.encryption,
                  'params-negotiated-mac':self.params.negotiated.mac,
                  'params-negotiated-compression':self.params.negotiated.compression,
                  
                  'crypto-client-enc':repr(self.crypto.client.enc),
                  'crypto-client-dec':repr(self.crypto.client.dec),
                  'crypto-server-enc':repr(self.crypto.server.enc),
                  'crypto-server-dec':repr(self.crypto.server.dec),
                  
                  'crypto-server-rsa-pubkey':repr(self.crypto.server.rsa.pubkey),
                  'crypto-server-rsa-privkey':repr(self.crypto.server.rsa.privkey),
                  
                  'crypto-session-encrypted_premaster_secret':repr(self.crypto.session.encrypted_premaster_secret),
                  'crypto-session-premaster_secret':repr(self.crypto.session.premaster_secret),
                  'crypto-session-master_secret':repr(self.crypto.session.master_secret),
                  
                  'crypto-session-randombytes-client':repr(self.crypto.session.randombytes.client),
                  'crypto-session-randombytes-server':repr(self.crypto.session.randombytes.server),
                  
                  'crypto-session-key-server-mac':repr(self.crypto.session.key.server.mac),
                  'crypto-session-key-server-encryption':repr(self.crypto.session.key.server.encryption),
                  'crypto-session-key-server-iv':repr(self.crypto.session.key.server.iv),
                  
                  'crypto-session-key-client-mac':repr(self.crypto.session.key.client.mac),
                  'crypto-session-key-client-encryption':repr(self.crypto.session.key.client.encryption),
                  'crypto-session-key-client-iv':repr(self.crypto.session.key.client.iv),
                  
                  'crypto-session-key-length-mac':self.crypto.session.key.length.mac,
                  'crypto-session-key-length-encryption':self.crypto.session.key.length.encryption,
                  'crypto-session-key-length-iv':self.crypto.session.key.length.iv,
                  }

        
        str = "<TLSSessionCtx: id=%(id)s"
        
        str +="\n\t params.handshake.client=%(params-handshake-client)s"
        str +="\n\t params.handshake.server=%(params-handshake-server)s"
        str +="\n\t params.negotiated.ciphersuite=%(params-negotiated-ciphersuite)s"
        str +="\n\t params.negotiated.key_exchange=%(params-negotiated-key_exchange)s"
        str +="\n\t params.negotiated.encryption=%(params-negotiated-encryption)s"
        str +="\n\t params.negotiated.mac=%(params-negotiated-mac)s"
        str +="\n\t params.negotiated.compression=%(params-negotiated-compression)s"
        
        str +="\n\t crypto.client.enc=%(crypto-client-enc)s"
        str +="\n\t crypto.client.dec=%(crypto-client-dec)s"
        str +="\n\t crypto.server.enc=%(crypto-server-enc)s"
        str +="\n\t crypto.server.dec=%(crypto-server-dec)s"
        
        str +="\n\t crypto.server.rsa.privkey=%(crypto-server-rsa-privkey)s"
        str +="\n\t crypto.server.rsa.pubkey=%(crypto-server-rsa-pubkey)s"
        
        str +="\n\t crypto.session.encrypted_premaster_secret=%(crypto-session-encrypted_premaster_secret)s"
        str +="\n\t crypto.session.premaster_secret=%(crypto-session-premaster_secret)s"
        str +="\n\t crypto.session.master_secret=%(crypto-session-master_secret)s"
        
        str +="\n\t crypto.session.randombytes.client=%(crypto-session-randombytes-client)s"
        str +="\n\t crypto.session.randombytes.server=%(crypto-session-randombytes-server)s"

        str +="\n\t crypto.session.key.client.mac=%(crypto-session-key-client-mac)s"
        str +="\n\t crypto.session.key.client.encryption=%(crypto-session-key-client-encryption)s"
        str +="\n\t crypto.session.key.cllient.iv=%(crypto-session-key-client-iv)s"

        str +="\n\t crypto.session.key.server.mac=%(crypto-session-key-server-mac)s"
        str +="\n\t crypto.session.key.server.encryption=%(crypto-session-key-server-encryption)s"
        str +="\n\t crypto.session.key.server.iv=%(crypto-session-key-server-iv)s"
        
        str +="\n\t crypto.session.key.length.mac=%(crypto-session-key-length-mac)s"
        str +="\n\t crypto.session.key.length.encryption=%(crypto-session-key-length-encryption)s"
        str +="\n\t crypto.session.key.length.iv=%(crypto-session-key-length-iv)s"
        
        str += "\n>"
        return str%params
    
    def insert(self, p):
         '''
         add packet to context
         '''
         self.packets.history.append(p)
         self.process(p)        # fill structs
         
    def process(self,p):
        '''
        fill context
        '''
        if p.haslayer(tls.TLSHandshake):
            # requires handshake messages
            if p.haslayer(tls.TLSClientHello):
                if not self.params.handshake.client:
                    self.params.handshake.client=p[tls.TLSClientHello]
                    
                    # fetch randombytes for crypto stuff
                    if not self.crypto.session.randombytes.client:
                        self.crypto.session.randombytes.client=struct.pack("!I",p[tls.TLSClientHello].gmt_unix_time)+p[tls.TLSClientHello].random_bytes
            if p.haslayer(tls.TLSServerHello):
                if not self.params.handshake.server:
                    self.params.handshake.server=p[tls.TLSServerHello]
                    #fetch randombytes
                    if not self.crypto.session.randombytes.server:
                        self.crypto.session.randombytes.server=struct.pack("!I",p[tls.TLSServerHello].gmt_unix_time)+p[tls.TLSServerHello].random_bytes
                # negotiated params
                if not self.params.negotiated.ciphersuite:
                    self.params.negotiated.ciphersuite=p[tls.TLSServerHello].cipher_suite
                    self.params.negotiated.compression=p[tls.TLSServerHello].compression_method
                    kex,enc,mac = describe_ciphersuite(self.params.negotiated.ciphersuite)
                    self.params.negotiated.key_exchange=kex
                    self.params.negotiated.encryption=enc
                    self.params.negotiated.mac=mac
            if p.haslayer(tls.TLSCertificateList):
                if self.params.negotiated.key_exchange and "RSA" in self.params.negotiated.key_exchange:
                    # fetch server pubkey // PKCS1_v1_5
                    cert = p[tls.TLSCertificateList].certificates[0].data
                    self.crypto.server.rsa.pubkey = PKCS1_v1_5.new(x509_extract_pubkey_from_der(cert))
                    # check for client privkey
                    
            # calculate key material
            if p.haslayer(tls.TLSClientKeyExchange) \
                    and self.crypto.server.rsa.privkey:  
                
                # FIXME: RSA_AES128_SHA1
                self.crypto.session.key.length.mac = 160/8
                self.crypto.session.key.length.encryption = 128/8
                self.crypto.session.key.length.iv = 16
                # calculate secrets and key material from encrypted key
                # if private_key is set we're going to decrypt the PremasterSecret and re-calc key material
                self.crypto.session.encrypted_premaster_secret = str(p[tls.TLSClientKeyExchange].payload)
                # decrypt epms -> pms
                self.crypto.session.premaster_secret = self.crypto.server.rsa.privkey.decrypt(self.crypto.session.encrypted_premaster_secret, None)
                secparams = TLSSecurityParameters()
                
                secparams.mac_key_length=self.crypto.session.key.length.mac
                secparams.enc_key_length=self.crypto.session.key.length.encryption
                secparams.fixed_iv_length=self.crypto.session.key.length.iv
                
                
                secparams.generate(self.crypto.session.premaster_secret, 
                                   self.crypto.session.randombytes.client,
                                   self.crypto.session.randombytes.server)
                
                self.crypto.session.master_secret = secparams.master_secret
                self.crypto.session.key.server.mac = secparams.server_write_MAC_key
                self.crypto.session.key.server.encryption = secparams.server_write_key
                self.crypto.session.key.server.iv = secparams.server_write_IV
        
    
                self.crypto.session.key.client.mac = secparams.client_write_MAC_key
                self.crypto.session.key.client.encryption = secparams.client_write_key
                self.crypto.session.key.client.iv = secparams.client_write_IV
    
                del secparams
                
                # create cypher objects
                # one for encryption and one for decryption to not mess up internal states
                self.crypto.client.enc = ciphersuite_factory(self.params.negotiated.ciphersuite,
                                                             key=self.crypto.session.key.client.encryption,
                                                             iv=self.crypto.session.key.client.iv)
                self.crypto.client.dec = ciphersuite_factory(self.params.negotiated.ciphersuite,
                                                             key=self.crypto.session.key.client.encryption,
                                                             iv=self.crypto.session.key.client.iv)
                self.crypto.server.enc = ciphersuite_factory(self.params.negotiated.ciphersuite,
                                                             key=self.crypto.session.key.server.encryption,
                                                             iv=self.crypto.session.key.server.iv)
                self.crypto.server.dec = ciphersuite_factory(self.params.negotiated.ciphersuite,
                                                             key=self.crypto.session.key.server.encryption,
                                                             iv=self.crypto.session.key.server.iv)
                
            # check whether crypto was set up
            
    def rsa_load_key(self, pem):
        key=RSA.importKey(pem)
        return PKCS1_v1_5.new(key)

    def rsa_load_from_file(self, pemfile):
        with open(pemfile,'r') as f:
          self.crypto.server.rsa.privkey = self.rsa_load_key(f.read())
    
    def rsa_load_privkey(self, pem):
        self.crypto.server.rsa.privkey = self.rsa_load_key(pem)
    
    def tlsciphertext_decrypt(self, p, cryptfunc):
        ret = tls.TLSRecord()
        ret.content_type, ret.version, ret.length = p[tls.TLSRecord].content_type, p[tls.TLSRecord].version, p[tls.TLSRecord].length
        enc_data = p[tls.TLSRecord].payload.load 
        
        #if self.packets.client.sequence==0:
        #    iv = self.crypto.session.key.client.iv
        decrypted = cryptfunc.decrypt(enc_data)
        
        plaintext = decrypted[:-self.crypto.session.key.length.mac-1]
        mac=decrypted[len(plaintext):]
        
        return ret/tls.TLSCiphertextDecrypted(plaintext)/tls.TLSCiphertextMAC(mac)
            

class TLSPRF(object):
    TLS_MD_CLIENT_FINISH_CONST = "client finished"
    TLS_MD_SERVER_FINISH_CONST = "server finished"
    TLS_MD_SERVER_WRITE_KEY_CONST = "server write key"
    TLS_MD_KEY_EXPANSION_CONST = "key expansion"
    TLS_MD_CLIENT_WRITE_KEY_CONST = "client write key"
    TLS_MD_SERVER_WRITE_KEY_CONST = "server write key"
    TLS_MD_IV_BLOCK_CONST = "IV block"
    TLS_MD_MASTER_SECRET_CONST = "master secret"
    
    
    def __init__(self, algorithm):
        self.algorithm = algorithm
    
    def p_hash(self, secret, seed):
        a_i = seed              # i=0
        ''' 1) 
        ##############i=0    hmac_hash(secret, seed+seed) +
        i=1    hmac_hash(secret, hmac_hash(secret, seed) +seed) +
        i=2    hmac_hash(secret, hmac_hash(secret, 
        '''
        
        #start at i=1
        while True:
            a_i = HMAC.new(key=secret, msg=a_i, digestmod=self.algorithm).digest()      # i=1
            yield HMAC.new(key=secret, msg=a_i+seed, digestmod=self.algorithm).digest()
        
    def prf(self, secret, label, seed):
        for block in self.p_hash(secret, label+seed):
            yield block
            
    def prf_numbytes(self, secret, label, random, numbytes):
        hs = (len(secret)+1)/2
        s1 = secret[:hs]
        s2 = secret[-hs:]
        
        #print "randlen=",len(random)
        #print "hs=",hs
        #print "s1=",s1
        #print "s2=",s2
        #print "label+random=",label+random
        #print "label=",label
        #1) compute P_md5(secret_part_1, label+random)   
        md5_hmac=''
        block=HMAC.new(key=s1, 
                       msg=label+random,
                       digestmod=MD5).digest() 
        while len(md5_hmac)<numbytes:
            md5_hmac += HMAC.new(key=s1, 
                             msg=block+label+random,
                             digestmod=MD5).digest()
            
            block = HMAC.new(key=s1, 
                             msg=block,
                             digestmod=MD5).digest()
            #print [ "%.2x"%ord(i) for i in md5_hmac]
            
        md5_hmac=md5_hmac[:numbytes]
        # sha stuff
        sha_hmac=''
        block=HMAC.new(key=s2, 
                       msg=label+random,
                       digestmod=SHA).digest() 
        while len(sha_hmac)<numbytes:
            sha_hmac += HMAC.new(key=s2, 
                             msg=block+label+random,
                             digestmod=SHA).digest()
            
            block = HMAC.new(key=s2, 
                             msg=block,
                             digestmod=SHA).digest()
            #print [ "%.2x"%ord(i) for i in sha_hmac]
        # XOR both strings
        sha_hmac=sha_hmac[:numbytes]              
        
        m = array.array("B",md5_hmac)
        s = array.array("B",sha_hmac)

        for i in xrange(numbytes):
            m[i] ^= s[i]
            #print "%0.2x"%m[i],
            
        return m.tostring()
        
        '''
        data  = ''
        for block in self.prf(secret,label,seed):
            data +=block
            if len(data)>=numbytes:
                return data[:numbytes]
        '''    
    def hmac(self, key, msg):
        return HMAC.new(key=key, msg=msg, digestmod=self.algorithm).digest()
    
    def hash(self, msg):
        return self.algorithm.new(msg).digest()
               
class TLSSecurityParameters(object):
    
    def __init__(self):
        self.client_write_MAC_key = None
        self.server_write_MAC_key= None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_IV = None
        self.server_write_IV = None
        
        self.mac_key_length = 160/8
        self.enc_key_length = 128/8
        self.fixed_iv_length = 16
        
        self.premaster_secret = None
        
        self.prf =TLSPRF(Crypto.Hash.SHA256)
        
    def __len__(self):
        return len(self.client_write_MAC_key
                   +self.server_write_MAC_key
                   +self.client_write_key
                   +self.server_write_key
                   +self.client_write_IV
                   +self.server_write_IV)
        
    def consume_bytes(self, data):
        i=0
        self.client_write_MAC_key = data[i:i+self.mac_key_length]
        i+=self.mac_key_length
        
        self.server_write_MAC_key= data[i:i+self.mac_key_length]
        i+=self.mac_key_length
        
        self.client_write_key = data[i:i+self.enc_key_length]
        i+=self.enc_key_length
        
        self.server_write_key = data[i:i+self.enc_key_length]
        i+=self.enc_key_length
        
        self.client_write_IV = data[i:i+self.fixed_iv_length]
        i+=self.fixed_iv_length
        
        self.server_write_IV = data[i:i+self.fixed_iv_length]
        i+=self.fixed_iv_length
        return i
    
    def __str__(self):
        s=[]
        for f in (f for f in dir(self) if "_write_" in f):
            s.append( "%20s | %s"%(f,repr(getattr(self,f))))
            
        
        s.append("%20s| %s"%("premaster_secret",repr(self.premaster_secret)))
        s.append("%20s| %s"%("master_secret",repr(self.master_secret)))
        s.append("%20s| %s"%("master_secret [bytes]",repr([ "%0.2x"%ord(i) for i in self.master_secret])))
        return "\n".join(s)
    
    def generate(self, pre_master_secret, client_random, server_random):
        
        
        self.master_secret = self.prf.prf_numbytes(pre_master_secret,
                                                   TLSPRF.TLS_MD_MASTER_SECRET_CONST,
                                                   client_random+server_random, 
                                                   numbytes=48)
        #print ">",repr(self.master_secret), len(self.master_secret)
        
        self.key_block = self.prf.prf_numbytes(self.master_secret,
                                               TLSPRF.TLS_MD_KEY_EXPANSION_CONST, 
                                               server_random+client_random, 
                                               numbytes=2*(self.mac_key_length+self.enc_key_length+self.fixed_iv_length) )
        
        #print ">>",repr(self.key_block), len(self.key_block)
        self.consume_bytes(self.key_block)
        # self



  
if __name__=="__main__":     
    pre_master_secret = "\03\01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
    client_random = 'a'*32
    server_random = 'z'*32

    '''
    p = TLSPRF(Crypto.Hash.SHA256)
    
    master_secret = p.prf_numbytes(pre_master_secret,TLSPRF.TLS_MD_MASTER_SECRET_CONST,client_random+server_random, numbytes=48)
    print repr(master_secret), len(master_secret)
    
    secparams = tls.TLSSecurityParameters()
    key_block = p.prf_numbytes(master_secret,TLSPRF.TLS_MD_KEY_EXPANSION_CONST, server_random+client_random, numbytes=2*(secparams.mac_key_length+secparams.enc_key_length+secparams.fixed_iv_length) )
    print repr(key_block), len(key_block)
    print secparams.consume_bytes(key_block)
    print secparams
    '''
    secparams = TLSSecurityParameters()
    secparams.generate(pre_master_secret, client_random, server_random)
    
    print repr(secparams.master_secret)
    print [ "%.2x"%ord(i) for i in secparams.master_secret]
    print '[x]  ',"Test: master_secret (tls1) .....",secparams.master_secret == 'C\'\x87\x12\xb1\xfe\xba6"\xc5t_y\x90\x8aw\xb6\xe8\x01#\x9f\xc1\x93\x90$\x0c\xc4Z\x17Q{b\x18\xdf\xcb?7\x0c\x97\xf1S)%\x1ez \xff\xb0'
    
    
    print "-----------------"
    # NOTE! - use different objects for enc/dec.
    cf_e= ciphersuite_factory("RSA_WITH_AES_128_CBC_SHA",'a'*16,'i'*16)
    cf_d= ciphersuite_factory("RSA_WITH_AES_128_CBC_SHA",'a'*16,'i'*16)
    plaintext="a"*251
    print '[x]  ',"Test: ciphersuite_factory .....", plaintext==cf_d.decrypt(cf_e.encrypt(plaintext))
    exit()
    
