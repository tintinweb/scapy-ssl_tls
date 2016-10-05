# -*- coding: utf-8 -*-

import binascii
import math
import random

from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from scapy.asn1.asn1 import ASN1_SEQUENCE


def rsa_public_from_der_certificate(certificate):
    # Extract subject_public_key_info field from X.509 certificate (see RFC3280)
    try:
        # try to extract pubkey from scapy.layers.x509 X509Cert type in case
        # der_certificate is of type X509Cert
        # Note: der_certificate may not be of type X509Cert if it wasn't
        # received completely, in that case, we'll try to extract it anyway
        # using the old method.
        # TODO: get rid of the old method and always expect X509Cert obj ?
        """
        Rebuild ASN1 SubjectPublicKeyInfo since X509Cert does not provide the full struct

        ASN1F_SEQUENCE(
                ASN1F_SEQUENCE(ASN1F_OID("pubkey_algo","1.2.840.113549.1.1.1"),
                               ASN1F_field("pk_value",ASN1_NULL(0))),
                ASN1F_BIT_STRING("pubkey","")
                ),
        """
        subject_public_key_info = ASN1_SEQUENCE([ASN1_SEQUENCE([certificate.pubkey_algo, certificate.pk_value]),
                                                 certificate.pubkey])
        return RSA.importKey(str(subject_public_key_info))
    except AttributeError:
        pass

    # Fallback method, may pot. allow to extract pubkey from incomplete der streams
    cert = DerSequence()
    cert.decode(certificate)

    tbs_certificate = DerSequence()
    tbs_certificate.decode(cert[0])       # first DER SEQUENCE

    # search for pubkey OID: rsaEncryption: "1.2.840.113549.1.1.1"
    # hex: 06 09 2A 86 48 86 F7 0D 01 01 01
    subject_public_key_info = None
    for seq in tbs_certificate:
        if not isinstance(seq, basestring):
            continue     # skip numerics and non sequence stuff
        if "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" in seq:
            subject_public_key_info = seq

    if subject_public_key_info is None:
        raise ValueError("could not find OID rsaEncryption 1.2.840.113549.1.1.1 in certificate")

    # Initialize RSA key
    return RSA.importKey(subject_public_key_info)


def rsa_public_from_pem_certificate(certificate):
    return rsa_public_from_der_certificate(pem_to_der(certificate))


def pem_to_der(certificate):
    # https://github.com/m4droid/U-Pasaporte/blob/7a00b344e97bb05265fd726f4125f0966dca6a5a/upasaporte/__init__.py
    lines = certificate.replace(" ", "").split()
    return binascii.a2b_base64("".join(lines[1:-1]))


def nb_bits(int_):
    return int(math.ceil(math.log(int_) / math.log(2)))


class AsymKeyStore(object):
    def __init__(self, name, public, private=None):
        self.name = name
        self.private = private
        self.public = public
        self.keys = (self.private, self.public)
        self.certificate = None

    @classmethod
    def from_private(cls, private):
        raise NotImplementedError()

    def __str__(self):
        template = """
{name}:
    certificate: {certificate}
    public: {public}
    private: {private}"""
        return template.format(name=self.name, certificate=repr(self.certificate), public=self.public,
                               private=self.private)


class EmptyAsymKeystore(AsymKeyStore):
    def __init__(self):
        super(EmptyAsymKeystore, self).__init__("Empty Keystore", None, None)


class RSAKeystore(AsymKeyStore):
    def __init__(self, public, private=None):
        super(RSAKeystore, self).__init__("RSA Keystore", public, private)

    @classmethod
    def from_der_certificate(cls, certificate):
        public = rsa_public_from_der_certificate(certificate)
        keystore = cls(public)
        keystore.certificate = certificate
        return keystore

    @classmethod
    def from_pem_certificate(cls, certificate):
        public = rsa_public_from_pem_certificate(certificate)
        keystore = cls(public)
        keystore.certificate = certificate
        return keystore

    @classmethod
    def from_private(cls, private):
        private = RSA.importKey(private)
        public = private.publickey()
        return cls(public, private)


class DSAKeystore(AsymKeyStore):
    def __init__(self, public, private=None):
        super(DSAKeystore, self).__init__("DSA Keystore", public, private)


class KexKeyStore(object):
    def __init__(self, name, public, private=None):
        self.name = name
        self.public = public
        self.private = private


class EmptyKexKeystore(KexKeyStore):
    def __init__(self):
        super(EmptyKexKeystore, self).__init__("Empty Kex Keystore", None, None)


class DHKeyStore(KexKeyStore):
    def __init__(self, g, p, public, private=None):
        self.g = g
        self.p = p
        self.size = nb_bits(self.p)
        super(DHKeyStore, self).__init__("DH Keystore", public, private)

    @classmethod
    def new_keypair(cls, g, p, private=None):
        # Client private key
        # Long story short, this provides 128bits of key space (sqrt(2**256)). TLS leaves this up to the implementation.
        # Another option is to gather random.randint(0, 2**nb_bits(p) - 1), but has little added security
        # In our case, since we don't care about security, it really doesn't matter what we pick
        private = private or random.randint(0, 2 ** 256 - 1)
        public = pow(g, private, p)
        return cls(g, p, public, private)

    def get_psk(self, public):
        return pow(public, self.private, self.p)

    def __str__(self):
        template = """
        {name}:
            generator: {g}
            modulus: {p}
            size: {size}
            public: {public}
            private: {private}"""
        return template.format(name=self.name, g=self.g, p=self.p, size=self.size, public=self.public,
                               private=self.private)
