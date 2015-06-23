#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html

import array
import binascii
import copy
import os
import struct
import zlib
import re
import pkcs7
import ssl_tls as tls

from collections import namedtuple
from Crypto.Cipher import AES, ARC2, ARC4, DES, DES3, PKCS1_v1_5
from Crypto.Hash import HMAC, MD5, SHA, SHA256
from Crypto.PublicKey import DSA, RSA
from Crypto.Util.asn1 import DerSequence
from scapy.asn1.asn1 import ASN1_SEQUENCE


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

REX_PEM = re.compile(r'(\-+BEGIN\s*([^\-]+)\-+(.*?)\-+END[^\-]+\-+)', re.DOTALL)
def pem_get_objects(data):
    d = {}
    for full, pemtype, pemdata in REX_PEM.findall(data):
        d[pemtype]={'data':data,
                    'full':full}
    return d

def x509_extract_pubkey_from_der(der_certificate):
    # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
    try:
        # try to extract pubkey from scapy.layers.x509 X509Cert type in case
        # der_certificate is of type X509Cert
        # Note: der_certificate may not be of type X509Cert if it wasn't 
        # received completely, in that case, we'll try to extract it anyway
        # using the old method. 
        # TODO: get rid of the old method and always expect X509Cert obj ?
        '''
        Rebuild ASN1 SubjectPublicKeyInfo since X509Cert does not provide the full struct
        
        ASN1F_SEQUENCE(
                ASN1F_SEQUENCE(ASN1F_OID("pubkey_algo","1.2.840.113549.1.1.1"),
                               ASN1F_field("pk_value",ASN1_NULL(0))),
                ASN1F_BIT_STRING("pubkey","")
                ),
        '''
        subjectPublicKeyInfo = ASN1_SEQUENCE([ ASN1_SEQUENCE([der_certificate.pubkey_algo,
                                                              der_certificate.pk_value]),
                                                der_certificate.pubkey,])
        return RSA.importKey(str(subjectPublicKeyInfo))
    except AttributeError:
        pass
    
    # Fallback method, may pot. allow to extract pubkey from incomplete der streams
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
    der = binascii.a2b_base64(''.join(lines[1:-1]))

    return x509_extract_pubkey_from_der(der)

class TLSSessionCtx(object):

    def __init__(self, client=True):
        self.client = client
        self.server = not self.client
        self.packets = namedtuple('packets',['history','client','server'])
        self.packets.history=[]         #packet history
        self.sec_params = None
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
                                                            "compression_algo",
                                                            "version",
                                                            "sig"
                                            ])
        self.params.negotiated.ciphersuite=None
        self.params.negotiated.key_exchange=None
        self.params.negotiated.encryption=None
        self.params.negotiated.mac=None
        self.params.negotiated.compression=None
        self.params.negotiated.compression_algo = None
        self.params.negotiated.version = None
        self.params.negotiated.sig = None
        self.compression = namedtuple("compression", ["method"])
        self.compression.method = None
        self.crypto = namedtuple('crypto', ['client','server'])
        self.crypto.client = namedtuple('client', ['enc', 'dec', "hmac"])
        self.crypto.client.enc = None
        self.crypto.client.dec = None
        self.crypto.client.hmac = None
        self.crypto.client.dh = namedtuple("dh", ["x", "y_c"])
        self.crypto.client.dh.x = None
        self.crypto.client.dh.y_c = None
        self.crypto.server = namedtuple('server', ['enc','dec','rsa', "hmac"])
        self.crypto.server.enc = None
        self.crypto.server.dec = None
        self.crypto.server.hmac = None
        self.crypto.server.rsa = namedtuple("rsa", ["pubkey","privkey"])
        self.crypto.server.rsa.pubkey = None
        self.crypto.server.rsa.privkey = None
        self.crypto.server.dsa = namedtuple("dsa", ["pubkey","privkey"])
        self.crypto.server.dsa.pubkey = None
        self.crypto.server.dsa.privkey = None
        self.crypto.server.dh = namedtuple("dh", ["p", "g", "x", "y_s"])
        self.crypto.server.dh.p = None
        self.crypto.server.dh.g = None
        self.crypto.server.dh.x = None
        self.crypto.server.dh.y_s = None
        self.crypto.session = namedtuple('session', ["encrypted_premaster_secret",
                                                     'premaster_secret',
                                                     'master_secret',
                                                     "prf"])
        
        self.crypto.session.encrypted_premaster_secret=None
        self.crypto.session.premaster_secret=None
        self.crypto.session.master_secret=None
        self.crypto.session.prf = TLSPRF(SHA256)
        self.crypto.session.randombytes = namedtuple('randombytes',['client','server'])
        self.crypto.session.randombytes.client=None
        self.crypto.session.randombytes.server=None
        
        self.crypto.session.key = namedtuple('key',['client','server'])
        self.crypto.session.key.server = namedtuple('server',['mac','encryption','iv', "seq_num"])
        self.crypto.session.key.server.mac = None
        self.crypto.session.key.server.encryption = None
        self.crypto.session.key.server.iv = None
        self.crypto.session.key.server.seq_num = 0

        self.crypto.session.key.client = namedtuple('client',['mac','encryption','iv', "seq_num"])
        self.crypto.session.key.client.mac = None
        self.crypto.session.key.client.encryption = None
        self.crypto.session.key.client.iv = None
        self.crypto.session.key.client.seq_num = 0
        
        self.crypto.session.key.length = namedtuple('length',['mac','encryption','iv'])
        self.crypto.session.key.length.mac = None
        self.crypto.session.key.length.encryption = None
        self.crypto.session.key.length.iv = None

    def __repr__(self):
        params = {'id':id(self),
                  'params-handshake-client':repr(self.params.handshake.client),
                  'params-handshake-server':repr(self.params.handshake.server),
                  "params-negotiated-version":tls.TLS_VERSIONS[self.params.negotiated.version],
                  'params-negotiated-ciphersuite':tls.TLS_CIPHER_SUITES[self.params.negotiated.ciphersuite],
                  'params-negotiated-key_exchange':self.params.negotiated.key_exchange,
                  'params-negotiated-encryption':self.params.negotiated.encryption,
                  'params-negotiated-mac':self.params.negotiated.mac,
                  'params-negotiated-compression':tls.TLS_COMPRESSION_METHODS[self.params.negotiated.compression],
                  
                  'crypto-client-enc':repr(self.crypto.client.enc),
                  'crypto-client-dec':repr(self.crypto.client.dec),
                  'crypto-server-enc':repr(self.crypto.server.enc),
                  'crypto-server-dec':repr(self.crypto.server.dec),
                  
                  'crypto-server-rsa-pubkey':repr(self.crypto.server.rsa.pubkey),
                  'crypto-server-rsa-privkey':repr(self.crypto.server.rsa.privkey),

                  "crypto-server-dsa-pubkey":repr(self.crypto.server.dsa.pubkey),
                  "crypto-server-dsa-privkey":repr(self.crypto.server.dsa.privkey),

                  "crypto-client-dh-x":repr(self.crypto.client.dh.x),
                  "crypto-client-dh-y_c":repr(self.crypto.client.dh.y_c),
                  "crypto-server-dh-p":repr(self.crypto.server.dh.p),
                  "crypto-server-dh-g":repr(self.crypto.server.dh.g),
                  "crypto-server-dh-x":repr(self.crypto.server.dh.x),
                  "crypto-server-dh-y_s":repr(self.crypto.server.dh.y_s),

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

        
        str_ = "<TLSSessionCtx: id=%(id)s"
        
        str_ +="\n\t params.handshake.client=%(params-handshake-client)s"
        str_ +="\n\t params.handshake.server=%(params-handshake-server)s"
        str_ +="\n\t params.negotiated.version=%(params-negotiated-version)s"
        str_ +="\n\t params.negotiated.ciphersuite=%(params-negotiated-ciphersuite)s"
        str_ +="\n\t params.negotiated.key_exchange=%(params-negotiated-key_exchange)s"
        str_ +="\n\t params.negotiated.encryption=%(params-negotiated-encryption)s"
        str_ +="\n\t params.negotiated.mac=%(params-negotiated-mac)s"
        str_ +="\n\t params.negotiated.compression=%(params-negotiated-compression)s"
        
        str_ +="\n\t crypto.client.enc=%(crypto-client-enc)s"
        str_ +="\n\t crypto.client.dec=%(crypto-client-dec)s"
        str_ +="\n\t crypto.server.enc=%(crypto-server-enc)s"
        str_ +="\n\t crypto.server.dec=%(crypto-server-dec)s"
        
        str_ +="\n\t crypto.server.rsa.privkey=%(crypto-server-rsa-privkey)s"
        str_ +="\n\t crypto.server.rsa.pubkey=%(crypto-server-rsa-pubkey)s"

        str_ +="\n\t crypto.server.dsa.privkey=%(crypto-server-dsa-privkey)s"
        str_ +="\n\t crypto.server.dsa.pubkey=%(crypto-server-dsa-pubkey)s"

        str_ +="\n\t crypto.client.dh.x=%(crypto-client-dh-x)s"
        str_ +="\n\t crypto.client.dh.y_c=%(crypto-client-dh-y_c)s"
        str_ +="\n\t crypto.server.dh.p=%(crypto-server-dh-p)s"
        str_ +="\n\t crypto.server.dh.g=%(crypto-server-dh-g)s"
        str_ +="\n\t crypto.server.dh.x=%(crypto-server-dh-x)s"
        str_ +="\n\t crypto.server.dh.y_s=%(crypto-server-dh-y_s)s"

        str_ +="\n\t crypto.session.encrypted_premaster_secret=%(crypto-session-encrypted_premaster_secret)s"
        str_ +="\n\t crypto.session.premaster_secret=%(crypto-session-premaster_secret)s"
        str_ +="\n\t crypto.session.master_secret=%(crypto-session-master_secret)s"
        
        str_ +="\n\t crypto.session.randombytes.client=%(crypto-session-randombytes-client)s"
        str_ +="\n\t crypto.session.randombytes.server=%(crypto-session-randombytes-server)s"

        str_ +="\n\t crypto.session.key.client.mac=%(crypto-session-key-client-mac)s"
        str_ +="\n\t crypto.session.key.client.encryption=%(crypto-session-key-client-encryption)s"
        str_ +="\n\t crypto.session.key.cllient.iv=%(crypto-session-key-client-iv)s"

        str_ +="\n\t crypto.session.key.server.mac=%(crypto-session-key-server-mac)s"
        str_ +="\n\t crypto.session.key.server.encryption=%(crypto-session-key-server-encryption)s"
        str_ +="\n\t crypto.session.key.server.iv=%(crypto-session-key-server-iv)s"
        
        str_ +="\n\t crypto.session.key.length.mac=%(crypto-session-key-length-mac)s"
        str_ +="\n\t crypto.session.key.length.encryption=%(crypto-session-key-length-encryption)s"
        str_ +="\n\t crypto.session.key.length.iv=%(crypto-session-key-length-iv)s"
        
        str_ += "\n>"
        return str_ % params
    
    def insert(self, p):
        '''
        add packet to context
        - unpack SSL.records and add them to history
        '''
        if p.haslayer(tls.SSL):
            ps = p[tls.SSL].records
        else:
            ps = [p]
        
        for p in ps:
            self.packets.history.append(p)
            self._process(p)    # fill structs
         
    def _process(self,p):
        '''
        fill context
        '''
        if p.haslayer(tls.TLSHandshake):
            # requires handshake messages
            if p.haslayer(tls.TLSClientHello):
                if not self.params.handshake.client:

                    self.params.handshake.client = p[tls.TLSClientHello]
                    self.params.negotiated.version = p[tls.TLSClientHello].version
                    # fetch randombytes for crypto stuff
                    if not self.crypto.session.randombytes.client:
                        self.crypto.session.randombytes.client = struct.pack("!I", p[tls.TLSClientHello].gmt_unix_time) + p[tls.TLSClientHello].random_bytes
                    # Generate a random PMS. Overriden at decryption time if private key is provided
                    if self.crypto.session.premaster_secret is None:
                        self.crypto.session.premaster_secret = self._generate_random_pms(self.params.negotiated.version)
            if p.haslayer(tls.TLSServerHello):
                if not self.params.handshake.server:
                    self.params.handshake.server = p[tls.TLSServerHello]
                    self.params.negotiated.version = p[tls.TLSServerHello].version
                    #fetch randombytes
                    if not self.crypto.session.randombytes.server:
                        self.crypto.session.randombytes.server = struct.pack("!I", p[tls.TLSServerHello].gmt_unix_time) + p[tls.TLSServerHello].random_bytes
                # negotiated params
                if not self.params.negotiated.ciphersuite:
                    self.params.negotiated.ciphersuite = p[tls.TLSServerHello].cipher_suite
                    self.params.negotiated.compression = p[tls.TLSServerHello].compression_method
                    try:
                        self.params.negotiated.compression_algo = TLSCompressionParameters.comp_params[self.params.negotiated.compression]["name"]
                        self.compression.method = TLSCompressionParameters.comp_params[self.params.negotiated.compression]["type"]
                    except KeyError:
                        raise KeyError("Compression method 0x%02x not supported" % self.params.negotiated.compression)
                    # Raises RuntimeError if we do not handle the cipher
                    try:
                        self.params.negotiated.key_exchange = TLSSecurityParameters.crypto_params[self.params.negotiated.ciphersuite]["key_exchange"]["name"]
                        self.params.negotiated.sig = TLSSecurityParameters.crypto_params[self.params.negotiated.ciphersuite]["key_exchange"]["sig"]
                        self.params.negotiated.encryption = (TLSSecurityParameters.crypto_params[self.params.negotiated.ciphersuite]["cipher"]["name"],
                                                         TLSSecurityParameters.crypto_params[self.params.negotiated.ciphersuite]["cipher"]["key_len"],
                                                         TLSSecurityParameters.crypto_params[self.params.negotiated.ciphersuite]["cipher"]["mode_name"])
                        self.params.negotiated.mac = TLSSecurityParameters.crypto_params[self.params.negotiated.ciphersuite]["hash"]["name"]
                    except KeyError:
                        raise RuntimeError("Cipher 0x%04x not supported" % self.params.negotiated.ciphersuite)

            if p.haslayer(tls.TLSCertificateList):
                # TODO: Probably don't want to do that if rsa_load_priv*() is called 
                if self.params.negotiated.key_exchange is not None and (self.params.negotiated.key_exchange == tls.TLSKexNames.RSA or self.params.negotiated.sig == RSA):
                    # fetch server pubkey // PKCS1_v1_5
                    cert = p[tls.TLSCertificateList].certificates[0].data
                    self.crypto.server.rsa.pubkey = PKCS1_v1_5.new(x509_extract_pubkey_from_der(str(cert)))
                    # TODO: In the future also handle kex = DH and extract static DH params from cert
                elif self.params.negotiated.key_exchange is not None and self.params.negotiated.sig == DSA:
                    # TODO: Handle DSA sig key loading here to allow sig checks
                    # Pycrypto doesn't currently have an interface to this.
                    # Filed bug https://github.com/dlitz/pycrypto/issues/137
                    # Could port the change manually from master
                    # Could move to cryptography.io which also supports TLS1.2 AES GCM modes
                    pass

            if p.haslayer(tls.TLSServerKeyExchange):
                # DHE case
                if p.haslayer(tls.TLSServerDHParams):
                    self.crypto.server.dh.p = p[tls.TLSServerDHParams].p
                    self.crypto.server.dh.g = p[tls.TLSServerDHParams].g
                    self.crypto.server.dh.y_s = p[tls.TLSServerDHParams].y_s

            # calculate key material
            if p.haslayer(tls.TLSClientKeyExchange):
                if self.params.negotiated.key_exchange == tls.TLSKexNames.RSA:
                    self.crypto.session.encrypted_premaster_secret = p[tls.TLSClientKeyExchange].data
                    # If we have the private key, let's decrypt the PMS
                    if self.crypto.server.rsa.privkey is not None:
                        self.crypto.session.premaster_secret = self.crypto.server.rsa.privkey.decrypt(self.crypto.session.encrypted_premaster_secret, None)
                elif self.params.negotiated.key_exchange == tls.TLSKexNames.DHE:
                    self.crypto.client.dh.y_c = p[tls.TLSClientKeyExchange].data

                explicit_iv = True if self.params.negotiated.version > tls.TLSVersion.TLS_1_0 else False
                self.sec_params = TLSSecurityParameters(self.params.negotiated.ciphersuite,
                                                        self.crypto.session.premaster_secret,
                                                        self.crypto.session.randombytes.client,
                                                        self.crypto.session.randombytes.server,
                                                        explicit_iv)
                self._assign_crypto_material(self.sec_params)

    def _assign_crypto_material(self, sec_params):
        self.crypto.session.key.length.mac = sec_params.negotiated_crypto_param["hash"]["type"].digest_size
        self.crypto.session.key.length.encryption = sec_params.negotiated_crypto_param["cipher"]["key_len"]
        self.crypto.session.key.length.iv = sec_params.negotiated_crypto_param["cipher"]["type"].block_size

        self.crypto.session.master_secret = sec_params.master_secret

        self.crypto.session.key.server.mac = sec_params.server_write_MAC_key
        self.crypto.session.key.server.encryption = sec_params.server_write_key
        self.crypto.session.key.server.iv = sec_params.server_write_IV

        self.crypto.session.key.client.mac = sec_params.client_write_MAC_key
        self.crypto.session.key.client.encryption = sec_params.client_write_key
        self.crypto.session.key.client.iv = sec_params.client_write_IV

        # Retrieve ciphers used for client/server encryption and decryption
        self.crypto.client.enc = sec_params.get_client_enc_cipher()
        self.crypto.client.dec = sec_params.get_client_dec_cipher()
        self.crypto.client.hmac = sec_params.get_client_hmac()
        self.crypto.server.enc = sec_params.get_server_enc_cipher()
        self.crypto.server.dec = sec_params.get_server_dec_cipher()
        self.crypto.server.hmac = sec_params.get_server_hmac()
        
    def _rsa_load_keys(self, priv_key):
        priv_key = RSA.importKey(priv_key)
        pub_key = priv_key.publickey()
        return (PKCS1_v1_5.new(priv_key), PKCS1_v1_5.new(pub_key))

    def rsa_load_keys_from_file(self, priv_key_file):
        with open(priv_key_file,'r') as f:
            # _rsa_load_keys expects one pem/der key per file.
            privkey = pem_get_objects(f.read()).get("RSA PRIVATE KEY",{}).get("full")
            self.crypto.server.rsa.privkey, self.crypto.server.rsa.pubkey = self._rsa_load_keys(privkey)

    def rsa_load_keys(self, priv_key):
        self.crypto.server.rsa.privkey, self.crypto.server.rsa.pubkey = self._rsa_load_keys(priv_key)

    def _generate_random_pms(self, version):
        return "%s%s" % (struct.pack("!H", version), os.urandom(46))

    def get_encrypted_pms(self, pms=None):
        cleartext = pms or self.crypto.session.premaster_secret
        if self.crypto.server.rsa.pubkey is not None:
            self.crypto.session.encrypted_premaster_secret = self.crypto.server.rsa.pubkey.encrypt(cleartext)
        else:
            raise ValueError("Cannot calculate encrypted MS. No server certificate found in connection")
        return self.crypto.session.encrypted_premaster_secret

    def get_client_dh_pubkey(self, x=None):
        # ValueError is propagated to caller both if hex or int conversion fail
        import math
        import random
        str_to_int = lambda x: int(binascii.hexlify(x), 16)
        def int_to_str(int_):
            hex_ = "%x" % int_
            return binascii.unhexlify("%s%s" % ("" if len(hex_) % 2 == 0 else "0", hex_))
        nb_bits = lambda x: int(math.ceil(math.log(x) / math.log(2)))
        p = str_to_int(self.crypto.server.dh.p)
        g = str_to_int(self.crypto.server.dh.g)
        y_s = str_to_int(self.crypto.server.dh.y_s)
        # Client private key
        # Long story short, this provides 128bits of key space (sqrt(2**256)). TLS leaves this up to the implementation.
        # Another option is to gather random.randint(0, 2**nb_bits(p) - 1), but has little added security
        # In our case, since we don't care about security, it really doesn't matter what we pick
        a = x or random.randint(0, 2**256 - 1)
        self.crypto.client.dh.x = int_to_str(a)
        self.crypto.client.dh.y_c = int_to_str(pow(g, a, p))
        # Per RFC 4346 section 8.1.2
        # Leading bytes of Z that contain all zero bits are stripped before it is used as the
        # pre_master_secret.
        self.crypto.session.premaster_secret = int_to_str(pow(y_s, a, p)).lstrip("\x00")
        return self.crypto.client.dh.y_c

    def get_client_kex_data(self, val=None):
        if self.params.negotiated.key_exchange == tls.TLSKexNames.RSA:
            return self.get_encrypted_pms(val)
        elif self.params.negotiated.key_exchange == tls.TLSKexNames.DHE:
            return self.get_client_dh_pubkey(val)
        else:
            raise NotImplementedError("Key exchange unknown or currently not supported")

    def get_verify_data(self, client=True, data=None):
        if client:
            label = TLSPRF.TLS_MD_CLIENT_FINISH_CONST
        else:
            label = TLSPRF.TLS_MD_SERVER_FINISH_CONST
        verify_data = []
        for pkt in self.packets.history:
            for handshake in (r[tls.TLSHandshake] for r in pkt if r.haslayer(tls.TLSHandshake)):
                if not handshake.haslayer(tls.TLSFinished) and not handshake.haslayer(tls.TLSHelloRequest):
                    verify_data.append(str(handshake))

        prf_verify_data = self.crypto.session.prf.prf_numbytes(self.crypto.session.master_secret,
                                                               label,
                                                               "%s%s" % (MD5.new("".join(verify_data)).digest(), SHA.new("".join(verify_data)).digest()),
                                                               numbytes=12)
        return prf_verify_data

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

class CryptoContainer(object):
    
    def __init__(self, tls_ctx, data="", content_type=tls.TLSContentType.APPLICATION_DATA):
        if tls_ctx is None:
            raise ValueError("Valid TLS session context required")
        self.tls_ctx = tls_ctx
        is_cbc = self.tls_ctx.sec_params.negotiated_crypto_param["cipher"]["mode"] != None
        if self.tls_ctx.params.negotiated.version > tls.TLSVersion.TLS_1_0 and is_cbc:
            self.explicit_iv = os.urandom(self.tls_ctx.crypto.session.key.length.iv)
        else:
            self.explicit_iv = ""
        self.data = data
        self.version = tls_ctx.params.negotiated.version
        self.content_type = content_type
        self.pkcs7 = pkcs7.PKCS7Encoder()
        if self.tls_ctx.client:
            # TODO: Needs concurrent safety if this ever goes concurrent
            self.hmac_handler = tls_ctx.crypto.client.hmac
            self.enc_cipher = tls_ctx.crypto.client.enc
            self.seq_number = tls_ctx.crypto.session.key.client.seq_num
            self.tls_ctx.crypto.session.key.client.seq_num += 1
        else:
            self.hmac_handler = tls_ctx.crypto.server.hmac
            self.enc_cipher = tls_ctx.crypto.server.enc
            self.seq_number = tls_ctx.crypto.session.key.server.seq_num
            self.tls_ctx.crypto.session.key.server.seq_num += 1
        # CBC mode
        self.hmac()
        if is_cbc:
            self.pad()
        # No padding otherwise
        else:
            self.padding = ""

    def hmac(self, seq=None, version=None, data_len=None):
        # Grab a copy of the initialized HMAC handler
        hmac = self.hmac_handler.copy()
        seq_ = struct.pack("!Q", seq or self.seq_number)
        content_type_ = struct.pack("!B", self.content_type)
        version_ = struct.pack("!H", version or self.version)
        len_ = struct.pack("!H", data_len or len(self.data))
        hmac.update("%s%s%s%s%s" % (seq_, content_type_, version_, len_, self.data))
        self.mac = hmac.digest()

    def pad(self):
        # "\xff" is a dummy trailing byte, to increase the length of imput
        # data by one byte. Any byte could do. This is to account for the
        # trailing padding_length byte in the RFC
        self.padding = self.pkcs7.get_padding("%s%s\xff" %(self.data, self.mac))

    def __str__(self):
        if len(self.padding) != 0:
            return "%s%s%s%s%s" % (self.explicit_iv, self.data, self.mac, self.padding, chr(len(self.padding)))
        else:
            return "%s%s%s" % (self.data, self.mac, self.padding)

    def __len__(self):
        return len(str(self))

    def encrypt(self, data=None):
        """ If data is passed in, caller is responsible for block alignment
        """
        return self.enc_cipher.encrypt(data or str(self))

class NullCipher(object):
    """ Implements a pycrypto like interface for the Null Cipher
    """
    
    block_size = 0
    key_size = 0
    
    @classmethod
    def new(cls, *args, **kwargs):
        return cls()
    
    def encrypt(self, cleartext):
        return cleartext
    
    def decrypt(self, ciphertext):
        return ciphertext

class NullHash(object):
    """ Implements a pycrypto like interface for the Null Hash
    """

    blocksize = 0
    digest_size = 0
    
    def __init__(self, *args, **kwargs):
        pass
    
    @classmethod
    def new(cls, *args, **kwargs):
        return cls(*args, **kwargs)
    
    def update(self, data):
        pass
    
    def digest(self):
        return ""
    
    def hexdigest(self):
        return ""
    
    def copy(self):
        return copy.deepcopy(self)

class DHE(object):
    pass
 
class TLSSecurityParameters(object):
    
    crypto_params = {
            tls.TLSCipherSuite.NULL_WITH_NULL_NULL:             {"name":tls.TLS_CIPHER_SUITES[0x0000], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":NullCipher, "name":"Null", "key_len":0, "mode":None, "mode_name":""}, "hash":{"type":NullHash, "name":"Null"}},
            tls.TLSCipherSuite.RSA_WITH_NULL_MD5:               {"name":tls.TLS_CIPHER_SUITES[0x0001], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":NullCipher, "name":"Null", "key_len":0, "mode":None, "mode_name":""}, "hash":{"type":MD5, "name":"MD5"}},
            tls.TLSCipherSuite.RSA_WITH_NULL_SHA:               {"name":tls.TLS_CIPHER_SUITES[0x0002], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":NullCipher, "name":"Null", "key_len":0, "mode":None, "mode_name":""}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_EXPORT_WITH_RC4_40_MD5:      {"name":tls.TLS_CIPHER_SUITES[0x0003], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC4, "name":"RC4", "key_len":5, "mode":None, "mode_name":"Stream"}, "hash":{"type":MD5, "name":"MD5"}},
            tls.TLSCipherSuite.RSA_WITH_RC4_128_MD5:            {"name":tls.TLS_CIPHER_SUITES[0x0004], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC4, "name":"RC4", "key_len":16, "mode":None, "mode_name":"Stream"}, "hash":{"type":MD5, "name":"MD5"}},
            tls.TLSCipherSuite.RSA_WITH_RC4_128_SHA:            {"name":tls.TLS_CIPHER_SUITES[0x0005], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC4, "name":"RC4", "key_len":16, "mode":None, "mode_name":"Stream"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_EXPORT_WITH_RC2_CBC_40_MD5:  {"name":tls.TLS_CIPHER_SUITES[0x0006], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC2, "name":"RC2", "key_len":5, "mode":ARC2.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":MD5, "name":"MD5"}},
            # 0x0007: RSA_WITH_IDEA_CBC_SHA => IDEA support would require python openssl bindings
            tls.TLSCipherSuite.RSA_EXPORT_WITH_DES40_CBC_SHA:   {"name":tls.TLS_CIPHER_SUITES[0x0008], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":DES, "name":"DES", "key_len":5, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_WITH_DES_CBC_SHA:            {"name":tls.TLS_CIPHER_SUITES[0x0009], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":DES, "name":"DES", "key_len":8, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_WITH_3DES_EDE_CBC_SHA:       {"name":tls.TLS_CIPHER_SUITES[0x000a], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":DES3, "name":"DES3", "key_len":24, "mode":DES3.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA:        {"name":tls.TLS_CIPHER_SUITES[0x002f], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":AES, "name":"AES", "key_len":16, "mode":AES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA:        {"name":tls.TLS_CIPHER_SUITES[0x0035], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":AES, "name":"AES", "key_len":32, "mode":AES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_WITH_NULL_SHA256:            {"name":tls.TLS_CIPHER_SUITES[0x003b], "export":False, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":NullCipher, "name":"Null", "key_len":0, "mode":None, "mode_name":""}, "hash":{"type":SHA256, "name":"SHA256"}},
            tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC4_56_MD5:  {"name":tls.TLS_CIPHER_SUITES[0x0060], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC4, "name":"RC4", "key_len":8, "mode":None, "mode_name":"Stream"}, "hash":{"type":MD5, "name":"MD5"}},
            tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC2_CBC_56_MD5: {"name":tls.TLS_CIPHER_SUITES[0x0061], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC2, "name":"RC2", "key_len":8, "mode":ARC2.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":MD5, "name":"MD5"}},
            tls.TLSCipherSuite.RSA_EXPORT1024_WITH_DES_CBC_SHA: {"name":tls.TLS_CIPHER_SUITES[0x0062], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":DES, "name":"DES", "key_len":8, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC4_56_SHA:  {"name":tls.TLS_CIPHER_SUITES[0x0064], "export":True, "key_exchange":{"type":RSA, "name":tls.TLSKexNames.RSA, "sig":None}, "cipher":{"type":ARC4, "name":"RC4", "key_len":8, "mode":None, "mode_name":"Stream"}, "hash":{"type":SHA, "name":"SHA"}},
            # 0x0084: RSA_WITH_CAMELLIA_256_CBC_SHA => Camelia support should use camcrypt or the camelia patch for pycrypto
            tls.TLSCipherSuite.DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:   {"name":tls.TLS_CIPHER_SUITES[0x0011], "export":True, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":DES, "name":"DES", "key_len":5, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_WITH_DES_CBC_SHA:        {"name":tls.TLS_CIPHER_SUITES[0x0012], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":DES, "name":"DES", "key_len":8, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_WITH_3DES_EDE_CBC_SHA:   {"name":tls.TLS_CIPHER_SUITES[0x0013], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":DES3, "name":"DES3", "key_len":24, "mode":DES3.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:   {"name":tls.TLS_CIPHER_SUITES[0x0014], "export":True, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":RSA}, "cipher":{"type":DES, "name":"DES", "key_len":5, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_RSA_WITH_DES_CBC_SHA:        {"name":tls.TLS_CIPHER_SUITES[0x0015], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":RSA}, "cipher":{"type":DES, "name":"DES", "key_len":8, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_RSA_WITH_3DES_EDE_CBC_SHA:   {"name":tls.TLS_CIPHER_SUITES[0x0016], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":RSA}, "cipher":{"type":DES3, "name":"DES3", "key_len":24, "mode":DES3.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA:    {"name":tls.TLS_CIPHER_SUITES[0x0032], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":AES, "name":"AES", "key_len":16, "mode":AES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA:    {"name":tls.TLS_CIPHER_SUITES[0x0033], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":RSA}, "cipher":{"type":AES, "name":"AES", "key_len":16, "mode":AES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA:    {"name":tls.TLS_CIPHER_SUITES[0x0038], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":AES, "name":"AES", "key_len":32, "mode":AES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA:    {"name":tls.TLS_CIPHER_SUITES[0x0039], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":RSA}, "cipher":{"type":AES, "name":"AES", "key_len":32, "mode":AES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA: {"name":tls.TLS_CIPHER_SUITES[0x0063], "export":True, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":DES, "name":"DES", "key_len":8, "mode":DES.MODE_CBC, "mode_name":"CBC"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_EXPORT1024_WITH_RC4_56_SHA:  {"name":tls.TLS_CIPHER_SUITES[0x0065], "export":True, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":ARC4, "name":"RC4", "key_len":8, "mode":None, "mode_name":"Stream"}, "hash":{"type":SHA, "name":"SHA"}},
            tls.TLSCipherSuite.DHE_DSS_WITH_RC4_128_SHA:            {"name":tls.TLS_CIPHER_SUITES[0x0066], "export":False, "key_exchange":{"type":DHE, "name":tls.TLSKexNames.DHE, "sig":DSA}, "cipher":{"type":ARC4, "name":"RC4", "key_len":16, "mode":None, "mode_name":"Stream"}, "hash":{"type":SHA, "name":"SHA"}},
            # 0x0087: DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => Camelia support should use camcrypt or the camelia patch for pycrypto
            # 0x0088: DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => Camelia support should use camcrypt or the camelia patch for pycrypto
            }
# Unsupported for now, until TLS1.2 and ECDHE support implemented
#         ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005
#         ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
#         ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f    
#         ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
#         SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xc021
#         SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xc022
#         TLS_FALLBACK_SCSV = 0x5600

    def __init__(self, cipher_suite, pms, client_random, server_random, explicit_iv=False):
        """ /!\ This class is not thread safe
        """
        try:
            self.negotiated_crypto_param = self.crypto_params[cipher_suite]
        except KeyError:
            raise RuntimeError("Cipher 0x%04x not supported" % cipher_suite)
        # Not validating lengths here, since sending a longuer PMS might be interesting
        self.pms = pms
        if len(client_random) != 32:
            raise ValueError("Client random must be 32 bytes")
        self.client_random = client_random
        if len(server_random) != 32:
            raise ValueError("Server random must be 32 bytes")
        self.server_random = server_random
        self.mac_key_length = self.negotiated_crypto_param["hash"]["type"].digest_size
        self.cipher_key_length = self.negotiated_crypto_param["cipher"]["key_len"]
        block_size = self.negotiated_crypto_param["cipher"]["type"].block_size
        # Stream ciphers have a block size of one, but IV should be 0
        self.iv_length = 0 if block_size == 1 else block_size
        self.explicit_iv = explicit_iv
        self.prf = TLSPRF(SHA256)
        self.__init_crypto(pms, client_random, server_random, explicit_iv)
    
    def get_client_hmac(self):
        return self.__client_hmac

    def get_server_hmac(self):
        return self.__server_hmac
    
    def get_server_enc_cipher(self):
        if self.explicit_iv and self.cipher_mode is not None:
            return self.cipher_type.new(self.server_write_key, mode=self.cipher_mode, IV=self.server_write_IV)
        else:
            return self.__server_enc_cipher
    
    def get_server_dec_cipher(self):
        if self.explicit_iv and self.cipher_mode is not None:
            return self.cipher_type.new(self.server_write_key, mode=self.cipher_mode, IV=self.server_write_IV)
        else:
            return self.__server_dec_cipher
    
    def get_client_enc_cipher(self):
        if self.explicit_iv and self.cipher_mode is not None:
            return self.cipher_type.new(self.client_write_key, mode=self.cipher_mode, IV=self.client_write_IV)
        else:
            return self.__client_enc_cipher
    
    def get_client_dec_cipher(self):
        if self.explicit_iv and self.cipher_mode is not None:
            return self.cipher_type.new(self.client_write_key, mode=self.cipher_mode, IV=self.client_write_IV)
        else:
            return self.__client_dec_cipher
#         
    def __init_key_material(self, data, explicit_iv):
        i = 0
        self.client_write_MAC_key = data[i:i+self.mac_key_length]
        i += self.mac_key_length
        self.server_write_MAC_key = data[i:i+self.mac_key_length]
        i += self.mac_key_length
        self.client_write_key = data[i:i+self.cipher_key_length]
        i += self.cipher_key_length
        self.server_write_key = data[i:i+self.cipher_key_length]
        i += self.cipher_key_length
        if explicit_iv:
            self.client_write_IV = "\x00"*self.iv_length
            self.server_write_IV = "\x00"*self.iv_length
        else:
            self.client_write_IV = data[i:i+self.iv_length]
            i += self.iv_length
            self.server_write_IV = data[i:i+self.iv_length]
            i += self.iv_length
        
    def __init_crypto(self, pms, client_random, server_random, explicit_iv):
        self.master_secret = self.prf.prf_numbytes(pms,
                                                   TLSPRF.TLS_MD_MASTER_SECRET_CONST,
                                                   client_random + server_random, 
                                                   numbytes=48)
        key_block = self.prf.prf_numbytes(self.master_secret,
                                          TLSPRF.TLS_MD_KEY_EXPANSION_CONST, 
                                          server_random + client_random, 
                                          numbytes=2*(self.mac_key_length + self.cipher_key_length + self.iv_length) )
        self.__init_key_material(key_block, explicit_iv)
        self.cipher_mode = self.negotiated_crypto_param["cipher"]["mode"]
        self.cipher_type = self.negotiated_crypto_param["cipher"]["type"]
        self.hash_type = self.negotiated_crypto_param["hash"]["type"]
        # Block ciphers
        if self.cipher_mode is not None:
            self.__client_enc_cipher = self.cipher_type.new(self.client_write_key, mode=self.cipher_mode, IV=self.client_write_IV)
            self.__client_dec_cipher = self.cipher_type.new(self.client_write_key, mode=self.cipher_mode, IV=self.client_write_IV)
            self.__server_enc_cipher = self.cipher_type.new(self.server_write_key, mode=self.cipher_mode, IV=self.server_write_IV)
            self.__server_dec_cipher = self.cipher_type.new(self.server_write_key, mode=self.cipher_mode, IV=self.server_write_IV)
        # Stream ciphers
        else:
            self.__client_enc_cipher = self.cipher_type.new(self.client_write_key)
            self.__client_dec_cipher = self.cipher_type.new(self.client_write_key)
            self.__server_enc_cipher = self.cipher_type.new(self.server_write_key)
            self.__server_dec_cipher = self.cipher_type.new(self.server_write_key)
        self.__client_hmac = HMAC.new(self.client_write_MAC_key, digestmod=self.hash_type)
        self.__server_hmac = HMAC.new(self.server_write_MAC_key, digestmod=self.hash_type)

    def __str__(self):
        s=[]
        for f in (f for f in dir(self) if "_write_" in f):
            s.append( "%20s | %s"%(f,repr(getattr(self,f))))
        s.append("%20s| %s" % ("premaster_secret", repr(self.pms)))
        s.append("%20s| %s" % ("master_secret", repr(self.master_secret)))
        s.append("%20s| %s" % ("master_secret [bytes]", binascii.hexlify(self.master_secret)))
        return "\n".join(s)

class NullCompression(object):
    """ Implements a zlib like interface for null compression
    """
    @staticmethod
    def compress(data):
        return data

    @staticmethod
    def decompress(data):
        return data

class TLSCompressionParameters(object):
    
    comp_params = {
                  tls.TLSCompressionMethod.NULL:    {"name":tls.TLS_COMPRESSION_METHODS[0x00], "type":NullCompression},
                  tls.TLSCompressionMethod.DEFLATE: {"name":tls.TLS_COMPRESSION_METHODS[0x01], "type":zlib}
                  }
