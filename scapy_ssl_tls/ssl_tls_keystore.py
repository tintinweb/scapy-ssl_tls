# -*- coding: utf-8 -*-

import binascii
import math
import random
import struct
import warnings

from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from scapy.asn1.asn1 import ASN1_SEQUENCE
import tinyec.ec as ec
import tinyec.registry as ec_reg


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
    if int_ == 0:
        return 0
    return int(math.ceil(math.log(int_) / math.log(2)))


def int_to_str(int_):
    hex_ = "%x" % int_
    return binascii.unhexlify("%s%s" % ("" if len(hex_) % 2 == 0 else "0", hex_))


def int_to_vector(num, fmt="!H"):
    num_str = int_to_str(num)
    return "%s%s" % (struct.pack(fmt, len(num_str)), num_str)


def str_to_int(str_):
    if str_ == "":
        return 0
    return int(binascii.hexlify(str_), 16)


def ansi_str_to_point(str_):
    if not str_.startswith("\x04"):
        raise ValueError("ANSI octet string missing point prefix (0x04)")
    str_ = str_[1:]
    if len(str_) % 2 != 0:
        raise ValueError("Can't parse curve point. Odd ANSI string length")
    half = len(str_) // 2
    return str_to_int(str_[:half]), str_to_int(str_[half:])


def point_to_ansi_str(point):
    return "\x04%s%s" % (int_to_str(point.x), int_to_str(point.y))


def tls_group_to_keystore(named_group_id, point_str):
    import scapy_ssl_tls.ssl_tls as tls
    try:
        point = ansi_str_to_point(point_str)
        named_group_name = tls.TLS_SUPPORTED_GROUPS[named_group_id]
    # Unknown curve case. Just record raw values, but do nothing with them
    except KeyError:
        keystore = ECDHKeyStore(None, point)
        warnings.warn("Unknown TLS defined group id: %d" % named_group_id)
    # We are on a known group
    else:
        try:
            group = ec_reg.get_curve(named_group_name)
            keystore = ECDHKeyStore(group, ec.Point(group, *point))
        except ValueError:
            keystore = ECDHKeyStore(None, point)
            warnings.warn("Unsupported TinyEC group: %s" % named_group_name)
    return keystore


class AsymKeyStore(object):

    def __init__(self, name, public, private=None):
        self.name = name
        self.private = private
        self.public = public
        if self.public is not None:
            self.size = nb_bits(self.public.n)
        else:
            self.size = 0
        self.keys = (self.private, self.public)
        self.certificate = None

    @classmethod
    def from_private(cls, private):
        raise NotImplementedError()

    def __str__(self):
        template = """{name}:
            certificate: {certificate}
            size: {size}
            public: {public}
            private: {private}"""
        return template.format(name=self.name, certificate=repr(self.certificate), size=self.size, public=self.public,
                               private=self.private)


class EmptyAsymKeystore(AsymKeyStore):

    def __init__(self):
        super(EmptyAsymKeystore, self).__init__("Empty Asymmetrical Keystore", None, None)


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
        template = """{name}:
            generator: {g}
            modulus: {p}
            size: {size}
            public: {public}
            private: {private}"""
        return template.format(name=self.name, g=self.g, p=self.p, size=self.size, public=self.public,
                               private=self.private)


class ECDHKeyStore(KexKeyStore):

    def __init__(self, curve, public, private=None):
        self.curve = curve
        self.public = public
        self.private = private
        if self.curve is None:
            self.unknown_curve = True
            self.size = 0
            self.keys = (self.private, self.public)
        else:
            self.unknown_curve = False
            self.size = nb_bits(self.curve.field.p)
            self.keys = ec.Keypair(curve, self.private, self.public)
        super(ECDHKeyStore, self).__init__("ECDH Keystore", public, private)

    @classmethod
    def from_keypair(cls, curve, keypair):
        return cls(curve, keypair.pub, keypair.priv)

    def __str__(self):
        template = """{name}:
            curve: {curve}
            size: {size}
            public: {public}
            private: {private}"""
        curve_name = "Unknown" if self.unknown_curve else self.curve.name
        return template.format(name=self.name, curve=curve_name, size=self.size, public=self.public,
                               private=self.private)


class SymKeyStore(object):

    def __init__(self, name, key=b""):
        self.name = name
        self.key = key
        self.size = len(self.key) * 8


class EmptySymKeyStore(SymKeyStore):

    def __init__(self):
        super(EmptySymKeyStore, self).__init__("Empty Symmetrical Keystore")


class CipherKeyStore(SymKeyStore):

    def __init__(self, properties, key, hmac=b"", iv=b""):
        self.properties = properties
        # Be consistent and track everything in bits
        self.block_size = self.properties["cipher"]["type"].block_size * 8
        self.hmac = hmac
        self.hmac_size = len(self.hmac) * 8
        self.iv = iv
        self.iv_size = len(self.iv) * 8
        prf = self.properties.get("prf")
        if prf is not None:
            self.prf_name = prf["name"]
            self.prf_size = prf["type"].digest_size * 8
        else:
            self.prf_name = "DEFAULT"
            self.prf_size = "DEFAULT"
        super(CipherKeyStore, self).__init__("%s Keystore" % self.properties["name"], key)

    def __str__(self):
        template = """{name}:
            {cipher_name} cipher:
                mode: {mode}
                key: {key}
                size: {size}
                block_size: {block_size}
                iv: {iv}
            {hmac_name} hmac:
                key: {hmac_key}
                size: {hmac_size}
            {prf_name} prf:
                size: {prf_size}"""
        return template.format(name=self.name, cipher_name=self.properties["cipher"]["name"],
                               mode=self.properties["cipher"]["mode_name"], key=repr(self.key), size=self.size,
                               block_size=self.block_size, iv=repr(self.iv), hmac_name=self.properties.get("hash", {}).get("name", ""),
                               hmac_key=repr(self.hmac), hmac_size=self.hmac_size, prf_name=self.prf_name,
                               prf_size=self.prf_size)
