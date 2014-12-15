#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html
import Crypto
from Crypto.Hash import HMAC
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
from base64 import b64decode
from Crypto.PublicKey import RSA
import hashlib

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
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]

    # Initialize RSA key
    return RSA.importKey(subjectPublicKeyInfo)

def x509_extract_pubkey_from_pem(public_key_string):
    #https://github.com/m4droid/U-Pasaporte/blob/7a00b344e97bb05265fd726f4125f0966dca6a5a/upasaporte/__init__.py
    # Convert from PEM to DER
    lines = public_key_string.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))

    return x509_extract_pubkey_from_der(der)

'''
def xxx():
    import Crypto.Cipher
    from Crypto.Cipher import AES
    key = '0123456789abcdef'
    IV = 16 * '\x00'           # Initialization vector: discussed later
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)
    
    text = 'j' * 64 + 'i' * 128
    ciphertext = encryptor.encrypt(text)
    
    print ciphertext
    '''


def ciphersuite_factory(ciphersuite):
    pass


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
            
    def prf_numbytes(self, secret, label, seed, numbytes):
        data  = ''
        for block in self.prf(secret,label,seed):
            data +=block
            if len(data)>=numbytes:
                return data[:numbytes]
            
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
        self.fixed_iv_length = 0
        
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
        return "\n".join(s)
    
    def generate(self, pre_master_secret, client_random, server_random):
        
        
        self.master_secret = self.prf.prf_numbytes(pre_master_secret,TLSPRF.TLS_MD_MASTER_SECRET_CONST,client_random+server_random, numbytes=48)
        print repr(self.master_secret), len(self.master_secret)
        
        self.key_block = self.prf.prf_numbytes(self.master_secret,TLSPRF.TLS_MD_KEY_EXPANSION_CONST, server_random+client_random, numbytes=2*(self.mac_key_length+self.enc_key_length+self.fixed_iv_length) )
        print repr(self.key_block), len(self.key_block)
        print self.consume_bytes(self.key_block)
        print self
    
if __name__=="__main__": 
    pre_master_secret = "hi"
    client_random = 'a'*28
    server_random = 'z'*28
    
    '''
    p = TLSPRF(Crypto.Hash.SHA256)
    
    master_secret = p.prf_numbytes(pre_master_secret,TLSPRF.TLS_MD_MASTER_SECRET_CONST,client_random+server_random, numbytes=48)
    print repr(master_secret), len(master_secret)
    
    secparams = TLSSecurityParameters()
    key_block = p.prf_numbytes(master_secret,TLSPRF.TLS_MD_KEY_EXPANSION_CONST, server_random+client_random, numbytes=2*(secparams.mac_key_length+secparams.enc_key_length+secparams.fixed_iv_length) )
    print repr(key_block), len(key_block)
    print secparams.consume_bytes(key_block)
    print secparams
    '''
    secparams = TLSSecurityParameters()
    secparams.generate(pre_master_secret, client_random, server_random)
    
    print repr(secparams.master_secret)