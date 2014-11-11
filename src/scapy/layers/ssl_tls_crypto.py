#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html

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