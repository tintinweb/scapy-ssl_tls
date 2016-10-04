# -*- coding: utf-8 -*-

import binascii

from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from scapy.asn1.asn1 import ASN1_SEQUENCE


def rsa_public_from_der_certificate(certificate):
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
        subjectPublicKeyInfo = ASN1_SEQUENCE([ASN1_SEQUENCE([certificate.pubkey_algo,
                                                             certificate.pk_value]),
                                              certificate.pubkey, ])
        return RSA.importKey(str(subjectPublicKeyInfo))
    except AttributeError:
        pass

    # Fallback method, may pot. allow to extract pubkey from incomplete der streams
    cert = DerSequence()
    cert.decode(certificate)

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


def rsa_public_from_pem_certificate(certificate):
    return rsa_public_from_der_certificate(pem_to_der(certificate))


def pem_to_der(certificate):
    # https://github.com/m4droid/U-Pasaporte/blob/7a00b344e97bb05265fd726f4125f0966dca6a5a/upasaporte/__init__.py
    lines = certificate.replace(" ", "").split()
    return binascii.a2b_base64("".join(lines[1:-1]))


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


class RSAKeystore(AsymKeyStore):
    def __init__(self, public, private=None):
        super(RSAKeystore, self).__init__("RSA", public, private)

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
        super(DSAKeystore, self).__init__("DSA", public, private)