#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html

import os
import time

from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.layers.inet import TCP, UDP


class BLenField(LenField):
    def __init__(self, name, default, fmt="I", adjust_i2m=lambda pkt, x:x, numbytes=None, length_of=None, count_of=None, adjust_m2i=lambda pkt, x:x):
        self.name = name
        self.adjust_i2m = adjust_i2m
        self.adjust_m2i = adjust_m2i
        self.numbytes = numbytes
        self.length_of = length_of
        self.count_of = count_of
        LenField.__init__(self, name, default, fmt)

        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!" + fmt
        self.default = self.any2i(None, default)
        self.sz = struct.calcsize(self.fmt) if not numbytes else numbytes
        self.owners = []
        
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        pack = struct.pack(self.fmt, self.i2m(pkt, val))
        if self.numbytes:
            pack = pack[len(pack) - self.numbytes:]
        return s + pack
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        upack_data = s[:self.sz]
        # prepend struct.calcsize()-len(data) bytes to satisfy struct.unpack
        upack_data = '\x00' * (struct.calcsize(self.fmt) - self.sz) + upack_data
            
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, upack_data)[0])
    
    def i2m(self, pkt, x):
        if x is None:
            if not (self.length_of or self.count_of):
                x = len(pkt.payload)
                x = self.adjust_i2m(pkt, x)
                return x
             
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust_i2m(pkt, f)
        return x
    def m2i(self, pkt, x):
        return self.adjust_m2i(pkt, x)

class XBLenField(BLenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))
    
class XLenField(LenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))
    
class XFieldLenField(FieldLenField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))   
    
class BEnumField(EnumField):
    def __init__(self, name, default, enum, fmt="!I", numbytes=None):
        EnumField.__init__(self, name, default, enum, fmt)
        self.numbytes = numbytes
        
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!" + fmt
        self.default = self.any2i(None, default)
        self.sz = struct.calcsize(self.fmt) if not numbytes else numbytes
        self.owners = []

    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        pack = struct.pack(self.fmt, self.i2m(pkt, val))
        if self.numbytes:
            pack = pack[len(pack) - self.numbytes:]
        return s + pack
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        upack_data = s[:self.sz]
        # prepend struct.calcsize()-len(data) bytes to satisfy struct.unpack
        upack_data = '\x00' * (struct.calcsize(self.fmt) - self.sz) + upack_data
            
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, upack_data)[0])
        
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return lhex(x)

class XBEnumField(BEnumField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))   
    
TLS_VERSIONS = {  0x0002:"SSL_2_0",
                  0x0300:"SSL_3_0",
                  0x0301:"TLS_1_0",
                  0x0302:"TLS_1_1",
                  0x0303:"TLS_1_2",
                  
                  0x0100:"PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
                  0xfeff:"DTLS_1_0",
                  0xfefd:"DTLS_1_1",
                  
                  }


TLS_CONTENT_TYPES = {0x14:"change_cipher_spec",
                        0x15:"alert",
                        0x16:"handshake",
                        0x17:"application_data",
                        0x18:"heartbeat",
                        0xff:"unknown"}

TLS_HANDSHAKE_TYPES = {0x00:"hello_request",
                        0x01:"client_hello",
                        0x02:"server_hello",
                        0x0b:"certificate",
                        0x0c:"server_key_exchange",
                        0x0d:"certificate_request",
                        0x0e:"server_hello_done",
                        0x0f:"certificate_verify",
                        0x10:"client_key_exchange",
                        0x14:"finished",
                        0x15:"certificate_url",
                        0x16:"certificate_stats",
                        0xff:"unknown"}

TLS_EXTENSION_TYPES = {
                       0x0000:"server_name",
                       0x0001:"max_fragment_length",
                       0x0002:"client_certificate_url",
                       0x0003:"trusted_ca_keys",
                       0x0004:"truncated_hmac",
                       0x0005:"status_request",
                       0x000a:"elliptic_curves",
                       0x000b:"ec_point_formats",
                       0x000d:"signature_algorithms",
                       0x000f:"heartbeat",
                       0x0010:"application_layer_protocol_negotiation",
                       0x0023:"session_ticket_tls",
                       0x3374:"next_protocol_negotiation",
                       0xff01:"renegotiationg_info",
                       }

TLS_ALERT_LEVELS = { 0x01: "warning",
                     0x02: "fatal",
                     0xff: "unknown", }

TLS_ALERT_DESCRIPTIONS = {    
                    0:"CLOSE_NOTIFY",
                    10:"UNEXPECTED_MESSAGE",
                    20:"BAD_RECORD_MAC",
                    21:"DECRYPTION_FAILED",
                    22:"RECORD_OVERFLOW",
                    30:"DECOMPRESSION_FAILURE",
                    40:"HANDSHAKE_FAILURE",
                    41:"NO_CERTIFICATE_RESERVED",
                    42:"BAD_CERTIFICATE",
                    43:"UNSUPPORTED_CERTIFICATE",
                    44:"CERTIFICATE_REVOKED",
                    45:"CERTIFICATE_EXPIRED",
                    46:"CERTIFICATE_UNKNOWN",
                    47:"ILLEGAL_PARAMETER",
                    48:"UNKNOWN_CA",
                    49:"ACCESS_DENIED",
                    50:"DECODE_ERROR",
                    51:"DECRYPT_ERROR",
                    60:"EXPORT_RESTRICTION",
                    70:"PROTOCOL_VERSION",
                    71:"INSUFFICIENT_SECURITY",
                    80:"INTERNAL_ERROR",
                    86:"INAPPROPRIATE_FALLBACK",
                    90:"USER_CANCELED",
                    100:"NO_RENEGOTIATION",
                    110:"UNSUPPORTED_EXTENSION",
                    111:"CERTIFICATE_UNOBTAINABLE",
                    112:"UNRECOGNIZED_NAME",
                    113:"BAD_CERTIFICATE_STATUS_RESPONSE",
                    114:"BAD_CERTIFICATE_HASH_VALUE",
                    255:"UNKNOWN" }

TLS_EXT_MAX_FRAGMENT_LENGTH_ENUM = {
                                    0x01: 2 ** 9,
                                    0x02: 2 ** 10,
                                    0x03: 2 ** 11,
                                    0x04: 2 ** 12,
                                    0xff: 'unknown',
                                    }


class TLSCipherSuite:
    '''
    make ciphersuites available as class props (autocompletion)
    '''
    NULL_WITH_NULL_NULL = 0x0000
    RSA_WITH_NULL_MD5 = 0x0001
    RSA_WITH_NULL_SHA1 = 0x0002
    RSA_WITH_NULL_SHA256 = 0x003b
    RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
    DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016    
    DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
    RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
    DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
    RSA_WITH_AES_128_CBC_SHA = 0x002f
    RSA_WITH_IDEA_CBC_SHA = 0x0007
    DHE_DSS_WITH_RC4_128_SHA = 0x0066
    RSA_WITH_RC4_128_SHA = 0x0005
    RSA_WITH_RC4_128_MD5 = 0x0004
    DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x0063
    RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x0062
    RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = 0x0061
    DHE_RSA_WITH_DES_CBC_SHA = 0x0015
    DHE_DSS_WITH_DES_CBC_SHA = 0x0012
    RSA_WITH_DES_CBC_SHA = 0x0009
    DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x0065
    RSA_EXPORT1024_WITH_RC4_56_SHA = 0x0064
    RSA_EXPORT1024_WITH_RC4_56_MD5 = 0x0060
    DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014
    DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011
    RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008
    RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006
    RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003
    RSA_WITH_AES_256_CBC_SHA = 0x0035
    DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038    
    DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f    
    ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xc021
    SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xc022
    DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087
    DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005
    RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_FALLBACK_SCSV = 0x5600

    
TLS_CIPHER_SUITES = dict((v, k) for k, v in TLSCipherSuite.__dict__.items() if not k.startswith("__"))

class TLSCompressionMethod:
    '''
    make compression methods available as class props (autocompletion)
    '''
    NULL = 0x00
    DEFLATE = 0x01
    
TLS_COMPRESSION_METHODS = dict((v, k) for k, v in TLSCompressionMethod.__dict__.items() if not k.startswith("__"))

class TLSRecord(Packet):
    name = "TLS Record"
    fields_desc = [ByteEnumField("content_type", 0xff, TLS_CONTENT_TYPES),
                   XShortEnumField("version", 0x0301, TLS_VERSIONS),
                   XLenField("length", None, fmt="!H"), ]

class TLSHandshake(Packet):
    name = "TLS Handshake"
    fields_desc = [ByteEnumField("type", 0xff, TLS_HANDSHAKE_TYPES),
                   XBLenField("length", None, fmt="!I", numbytes=3), ]


class TLSServerName(Packet):
    name = "TLS Servername"
    fields_desc = [ByteEnumField("type", 0x00, {0x00:"host"}),
                  XFieldLenField("length", None, length_of="data", fmt="H"),
                  StrLenField("data", "", length_from=lambda x:x.length),
                  ]
    
class TLSServerNameIndication(Packet):
    name = "TLS Extension Servername Indication"
    fields_desc = [XFieldLenField("length", None, length_of="server_names", fmt="H"),
                   PacketListField("server_names", None, TLSServerName, length_from=lambda x:x.length),
                  ]
#https://tools.ietf.org/html/rfc7301
class TLSALPNProtocol(Packet):
    name = "TLS ALPN Protocol"
    fields_desc = [
                  XFieldLenField("length", None, length_of="data", fmt="B"),
                  StrLenField("data", "", length_from=lambda x:x.length),
                  ]
    
class TLSALPN(Packet):
    name = "TLS Application-Layer Protocol Negotiation"
    fields_desc = [XFieldLenField("length", None, length_of="protocol_name_list", fmt="H"),
                   PacketListField("protocol_name_list", None, TLSALPNProtocol, length_from=lambda x:x.length),
                  ]

class TLSExtension(Packet):
    name = "TLS Extension"
    fields_desc = [XShortEnumField("type", 0x0000, TLS_EXTENSION_TYPES),
                   XLenField("length", None, fmt="!H"),
                  ]

    def extract_padding(self, s):
        return s[:self.length],s[self.length:]

# https://www.ietf.org/rfc/rfc3546.txt
class TLSExtMaxFragmentLength(Packet):
    name = "TLS Extension Max Fragment Length"
    fields_desc = [ByteEnumField("max_fragment_length", 0xff, TLS_EXT_MAX_FRAGMENT_LENGTH_ENUM)]
    
    def extract_padding(self, s):
        return '', s
    
CERT_CHAIN_TYPE = { 0x00: 'individual_certs',
                    0x01: 'pkipath',
                    0xff: 'unknown'}
TLS_TYPE_BOOLEAN = {0x00: 'false',
                    0x01: 'true'}

class TLSURLAndOptionalHash(Packet):
    name = "TLS Extension Certificate URL/Hash"
    fields_desc = [XFieldLenField("url_length", None, length_of="url", fmt="H"),
                  StrLenField("url", "", length_from=lambda x:x.url_length),
                  ByteEnumField("hash_present", 0x00, TLS_TYPE_BOOLEAN),
                  StrLenField("sha1hash", "", length_from=lambda x:20 if x.hash_present else 0),  # opaque SHA1Hash[20];
                  ]
    
class TLSExtCertificateURL(Packet):
    name = "TLS Extension Certificate URL"
    fields_desc = [ByteEnumField("type", 0xff, CERT_CHAIN_TYPE),
                   XFieldLenField("length", None, length_of="certificate_urls", fmt="H"),
                   PacketListField("certificate_urls", None, TLSURLAndOptionalHash, length_from=lambda x:x.length)
                   ]
    def extract_padding(self, s):
        return '', s

TLS_EXT_EC_POINT_FORMATS = {0x00:'uncompressed',
                            0x01:'ansiX962_compressed_prime',
                            0x02:'ansiX962_compressed_char2'}
class TLSExtECPointsFormat(Packet):
    name = "TLS Extension EC Points Format"
    fields_desc = [
                   XFieldLenField("length", None, length_of="ec_point_formats", fmt="B"),
                   FieldListField("ec_point_formats", None, ByteEnumField("ec_point_format", None, TLS_EXT_EC_POINT_FORMATS), length_from=lambda x:x.length),
                  ]
    def extract_padding(self, s):
        return '', s
TLS_EXT_ELLIPTIC_CURVES = {0x000e:'sect571r1',
                            }
class TLSExtEllipticCurves(Packet):
    name = "TLS Extension Elliptic Curves"
    fields_desc = [
                   XFieldLenField("length", None, length_of="elliptic_curves", fmt="H"),
                   FieldListField("elliptic_curves", None, ShortEnumField("elliptic_curve", None, TLS_EXT_ELLIPTIC_CURVES), length_from=lambda x:x.length),
                  ]
    def extract_padding(self, s):
        return '', s
    
class TLSExtHeartbeat(Packet):
    name = "TLS Extension HeartBeat"
    fields_desc = [StrFixedLenField("mode", 0x01, 0x01)
                  ]
    def extract_padding(self, s):
        return '', s

class TLSHelloRequest(Packet):
    name = "TLS Hello Request"
    fields_desc = []

class TLSClientHello(Packet):
    name = "TLS Client Hello"
    fields_desc = [XShortEnumField("version", 0x0301, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
    
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   FieldListField("cipher_suites", None, XShortEnumField("cipher", None, TLS_CIPHER_SUITES), length_from=lambda x:x.cipher_suites_length),
                   
                   XFieldLenField("compression_methods_length", None, length_of="compression_methods", fmt="B"),
                   FieldListField("compression_methods", None, ByteEnumField("compression", None, TLS_COMPRESSION_METHODS), length_from=lambda x:x.compression_methods_length),
                   
                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length),
                   ] 

    
class TLSServerHello(Packet):
    name = "TLS Server Hello"
    fields_desc = [XShortEnumField("version", 0x0301, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),

                   XShortEnumField("cipher_suite", 0x0000, TLS_CIPHER_SUITES),
                   ByteEnumField("compression_method", 0x00, TLS_COMPRESSION_METHODS),

                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length),
                   ]


class TLSAlert(Packet):
    name = "TLS Alert"
    fields_desc = [ByteEnumField("level", 0xff, TLS_ALERT_LEVELS),
                  ByteEnumField("description", 0xff, TLS_ALERT_DESCRIPTIONS),
                  ]


class TLSHeartBeat(Packet):
    name = "TLS Extension HeartBeat"
    fields_desc = [ByteEnumField("type", 0x01, {0x01:"request"}),
                  FieldLenField("length", None, length_of="data", fmt="H"),
                  StrLenField("data", "", length_from=lambda x:x.length),
                  StrLenField("padding", "", length_from=lambda x: 'P' * (16 - x.length)),
                  ]

class TLSClientKeyExchange(Packet):
    name = "TLS Client Key Exchange"
    fields_desc = [ XBLenField("length", None, fmt="!H",) ]

class TLSServerKeyExchange(Packet):
    name = "TLS Client Key Exchange"
    fields_desc = [ XBLenField("length", None, fmt="!H") ]
    
class TLSKexParamEncryptedPremasterSecret(Packet):
    name = "TLS Kex encrypted PreMasterSecret"
    fields_desc = [  # FieldLenField("length",None,length_of="data",fmt="H"),
                    StrLenField("data", None) ]

class TLSKexParamDH(Packet):
    name = "TLS Kex DH Params"
    fields_desc = [  # FieldLenField("length",None,length_of="data",fmt="H"),
                    StrLenField("data", None) ]

class TLSFinished(Packet):
    name = "TLS Handshake Finished"
    fields_desc = [  # FieldLenField("length",None,length_of="data",fmt="H"),
                    StrLenField("data", None) ]

class TLSDHServerParams(Packet):
    name = "TLS Diffie-Hellman Server Params"
    fields_desc = [XFieldLenField("p_length", None, length_of="p", fmt="!H"),
                   StrLenField("p", '', length_from=lambda x:x.p_length),
                   XFieldLenField("g_length", None, length_of="g", fmt="!H"),
                   StrLenField("g", '', length_from=lambda x:x.g_length),
                   XFieldLenField("pubkey_length", None, length_of="pubkey", fmt="!H"),
                   StrLenField("pubkey", '', length_from=lambda x:x.pubkey_length),
                   XFieldLenField("signature_length", None, length_of="signature", fmt="!H"),
                   StrLenField("signature", '', length_from=lambda x:x.signature_length), ]
                   
class TLSServerHelloDone(Packet):
    name = "TLS Server Hello Done"
    fields_desc = [ XBLenField("length", None, fmt="!I", numbytes=3),
                    StrLenField("data", "", length_from=lambda x:x.length), ]
    
class TLSCertificate(Packet):
    name = "TLS Certificate"
    fields_desc = [ XBLenField("length", None, length_of="data", fmt="!I", numbytes=3),
                    StrLenField("data", "", length_from=lambda x:x.length), ]  # BERcodec_Object.dec(data,context=ASN1_Class_X509)
    
    def extract_padding(self,s):
        return s[self.length:],s[:self.length]

    
class TLSCertificateList(Packet):
    name = "TLS Certificate List"
    fields_desc = [
                   XBLenField("length", None, length_of="certificates", fmt="!I", numbytes=3),
                   PacketListField("certificates", None, TLSCertificate, length_from=lambda x:x.length),
                  ]   

    def extract_padding(self,s):
        return s[self.length:],s[:self.length]    

class TLSChangeCipherSpec(Packet):
    name = "TLS ChangeCipherSpec"
    fields_desc = [ StrField("message", '\x01', fmt="H")]

class TLSCiphertext(Packet):
    name = "TLS Ciphertext"
    fields_desc = [ StrField("data", None, fmt="H"),
                    StrField("mac", None, fmt="H")]

class TLSPlaintext(Packet):
    name = "TLS Plaintext"
    fields_desc = [ StrField("data", None, fmt="H") ]

class DTLSRecord(Packet):
    name = "DTLS Record"
    fields_desc = [ByteEnumField("content_type", 0xff, TLS_CONTENT_TYPES),
                   XShortEnumField("version", 0x0301, TLS_VERSIONS),
                   ShortField("epoch", None),
                   XBLenField("sequence", None, fmt="!Q", numbytes=6),
                   XLenField("length", None, fmt="!H"), ]

class DTLSHandshake(Packet):
    name = "DTLS Handshake"
    fields_desc = TLSHandshake.fields_desc + [
                   ShortField("sequence", None),
                   XBLenField("fragment_offset", None, fmt="!I", numbytes=3),
                   XBLenField("length", None, fmt="!I", numbytes=3),
                   ]

class DTLSClientHello(Packet):
    name = "DTLS Client Hello"
    fields_desc = [XShortEnumField("version", 0xfeff, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
                   
                   XFieldLenField("cookie_length", None, length_of="cookie", fmt="B"),
                   StrLenField("cookie", '', length_from=lambda x:x.cookie_length),
                   
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   FieldListField("cipher_suites", None, XShortEnumField("cipher", None, TLS_CIPHER_SUITES), length_from=lambda x:x.cipher_suites_length),
                   
                   XFieldLenField("compression_methods_length", None, length_of="compression_methods", fmt="B"),
                   FieldListField("compression_methods", None, ByteEnumField("compression", None, TLS_COMPRESSION_METHODS), length_from=lambda x:x.compression_methods_length),
                   
                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extension_length),
                   ]   
    
SSLv2_CERTIFICATE_TYPES = { 0x01: 'x.509'}

class DTLSHelloVerify(Packet):
    name = "DTLS Hello Verify"
    fields_desc = [XShortEnumField("version", 0xfeff, TLS_VERSIONS),
                   XFieldLenField("cookie_length", None, length_of="cookie", fmt="B"),
                   StrLenField("cookie", '', length_from=lambda x:x.cookie_length),
                   ]
    
    
SSLv2_MESSAGE_TYPES = {0x01:'client_hello',
                     0x04: 'server_hello',
                     0x02: 'client_master_key'}


class SSLv2CipherSuite:
    '''
    make ciphersuites available as class props (autocompletion)
    '''
    DES_192_EDE3_CBC_WITH_MD5 = 0x0700c0
    IDEA_128_CBC_WITH_MD5 = 0x050080
    RC2_CBC_128_CBC_WITH_MD5 = 0x030080
    RC4_128_WITH_MD5 = 0x010080
    RC4_64_WITH_MD5 = 0x080080
    DES_64_CBC_WITH_MD5 = 0x060040
    RC2_CBC_128_CBC_WITH_MD5 = 0x040080
    RC4_128_EXPORT40_WITH_MD5 = 0x020080
    
SSL2_CIPHER_SUITES = dict((v, k) for k, v in SSLv2CipherSuite.__dict__.items() if not k.startswith("__"))


class SSLv2Record(Packet):
    name = "SSLv2 Record"
    fields_desc = [XBLenField("length", None, fmt="!H", adjust_i2m=lambda pkt, x: x + 0x8000 + 1, adjust_m2i=lambda pkt, x:x - 0x8000),  # length=halfbyte+byte with MSB(high(1stbyte)) =1 || +1 for lengt(content_type)
                   ByteEnumField("content_type", 0xff, SSLv2_MESSAGE_TYPES),
                   ]

class SSLv2ClientHello(Packet):
    name = "SSLv2 Client Hello"
    fields_desc = [
                   XShortEnumField("version", 0x0002, TLS_VERSIONS),

                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="H"),
                   XFieldLenField("challenge_length", None, length_of="challenge", fmt="H"),
                   
                   FieldListField("cipher_suites", None, XBEnumField("cipher", None, SSL2_CIPHER_SUITES, fmt="!I", numbytes=3), length_from=lambda x:x.cipher_suites_length),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
                   StrLenField("challenge", '', length_from=lambda x:x.challenge_length),
                   ]
    
    
SSLv2_CERTIFICATE_TYPES = { 0x01: 'x.509'}


class SSLv2ServerHello(Packet):
    name = "SSLv2 Server Hello"
    fields_desc = [
                   ByteEnumField("session_id_hit", 0x00, TLS_TYPE_BOOLEAN),
                   ByteEnumField("certificate_type", 0x01, SSLv2_CERTIFICATE_TYPES),
                   XShortEnumField("version", 0x0002, TLS_VERSIONS),

                   XFieldLenField("certificate_length", None, length_of="certificates", fmt="H"),
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   XFieldLenField("connection_id_length", None, length_of="connection_id", fmt="H"),
                   
                   StrLenField("certificates", '', length_from=lambda x:x.certificates_length),
                   FieldListField("cipher_suites", None, XBEnumField("cipher", None, SSL2_CIPHER_SUITES, fmt="!I", numbytes=3), length_from=lambda x:x.cipher_suites_length),
                   StrLenField("connection_id", '', length_from=lambda x:x.connection_id_length),
                   ]

class SSLv2ClientMasterKey(Packet):
    name = "SSLv2 Client Master Key"
    fields_desc = [
                   XBEnumField("cipher_suite", 0x0002, SSL2_CIPHER_SUITES, fmt="!I", numbytes=3),  # fixme: 3byte wide

                   XFieldLenField("clear_key_length", None, length_of="clear_key", fmt="H"),
                   XFieldLenField("encrypted_key_length", None, length_of="encrypted_key", fmt="H"),
                   XFieldLenField("key_argument_length", None, length_of="key_argument", fmt="H"),
                   
                   StrLenField("clear_key", '', length_from=lambda x:x.clear_key_length),
                   StrLenField("encrypted_key", '', length_from=lambda x:x.clear_key_length),
                   StrLenField("key_argument", '', length_from=lambda x:x.key_argument_length),
                   ]
    


# entry class
class SSL(Packet):
    '''
    COMPOUND CLASS for SSL
    '''
    name = "SSL/TLS"
    fields_desc = [PacketListField("records", None, TLSRecord)]
    
    def pre_dissect(self, s):
        # figure out if we're UDP or TCP
        
        if self.underlayer and self.underlayer.haslayer(UDP):
            self.guessed_next_layer = DTLSRecord
        elif ord(s[0]) & 0x80:
            # SSLv2 Header
            self.guessed_next_layer = SSLv2Record
        else:
            self.guessed_next_layer = TLSRecord
        self.fields_desc = [PacketListField("records", None, self.guessed_next_layer)]
        return s

    def do_dissect(self, s):
        pos = 0
        cls = self.guessed_next_layer  # FIXME: detect DTLS
        cls_len = len(cls())
        
        # do_dissect is responsible for initializing fields, see packet.py::do_dissect
        # inspired by scapys original do_dissect we iterate over all fields in
        # fields_desc even though we know that we only have on field call records
        flist = self.fields_desc[:]
        flist.reverse()
        while s and flist:
            f = flist.pop()
            try:
                while pos <= len(s):
                # consume payloads and add them to records list
                    record = cls(s[pos:], _internal=1)  # FIXME: performance
                    layer_len = cls_len + record.length
                    if layer_len == None:
                        break
                    record = cls(s[pos:pos + layer_len])
                    pos += layer_len
                    # to make 'records' appear in 'fields' it must
                    # be assigned once before appending
                    self.fields[f.name] = record
            except TypeError:
                pass
        return s[pos:]


    def encrypt(self, master_secret):
        pass
    
    def encrypt_stream(self):
        '''
              HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
                     TLSCompressed.version + TLSCompressed.length +
                     TLSCompressed.fragment));
        '''
        pass
    
    def decrypt(self, master_secret): pass
    
    def compress(self): pass
    def decompress(self): pass

def tls_handshake_handler(pkt, tls_ctx, client):
    if pkt.haslayer(TLSFinished):
        return (0x16, tls_ctx.get_verify_data())

cleartext_handler = { TLSPlaintext: lambda pkt, tls_ctx, client: (0x17, pkt.data),
                      TLSHandshake: tls_handshake_handler,
                      TLSChangeCipherSpec: lambda pkt, tls_ctx, client: (0x14, str(pkt)),
                      TLSAlert: lambda pkt, tls_ctx, client: (0x15, str(pkt)) }

def to_raw(pkt, tls_ctx, client=True, include_record=False, compress_hook=None, pre_encrypt_hook=None, encrypt_hook=None):
    import ssl_tls_crypto as tlsc

    if tls_ctx is None:
        raise ValueError("A valid TLS session context must be provided")
    comp_method = tls_ctx.compression.method

    content_type, data = None, None
    for tls_proto, handler in cleartext_handler.iteritems():
        if pkt.haslayer(tls_proto):
            content_type, data = handler(pkt[tls_proto], tls_ctx, client)
    if content_type is None and data is None:
        raise KeyError("Unhandled TLS protocol")

    if compress_hook is not None:
        post_compress_data = compress_hook(comp_method, data)
    else:
        post_compress_data = comp_method.compress(data)

    if pre_encrypt_hook is not None:
        cleartext, mac, padding = pre_encrypt_hook(post_compress_data)
        crypto_container = tlsc.CryptoContainer(tls_ctx, cleartext, content_type, client)
        crypto_container.mac = mac
        crypto_container.padding = padding
    else:
        cleartext = post_compress_data
        crypto_container = tlsc.CryptoContainer(tls_ctx, cleartext, content_type, client)
        mac = crypto_container.mac
        padding = crypto_container.padding

    if encrypt_hook is not None:
        ciphertext = encrypt_hook(cleartext, mac, padding)
    else:
        ciphertext = crypto_container.encrypt()

    if include_record:
        tls_ciphertext = TLSRecord(version=tls_ctx.params.negotiated.version, content_type=content_type)/ciphertext
    else:
        tls_ciphertext = ciphertext
    return tls_ciphertext

# bind magic
bind_layers(TCP, SSL, dport=443)
bind_layers(TCP, SSL, sport=443)
bind_layers(UDP, SSL, dport=4433)
bind_layers(UDP, SSL, sport=4433)

# TLSRecord
bind_layers(TLSRecord, TLSChangeCipherSpec, {'content_type':0x14})
bind_layers(TLSRecord, TLSHeartBeat, {'content_type':0x18})
bind_layers(TLSRecord, TLSAlert, {'content_type':0x15})

bind_layers(TLSRecord, TLSHandshake, {'content_type':0x16})
# --> handshake proto
bind_layers(TLSHandshake, TLSHelloRequest, {'type':0x00})
bind_layers(TLSHandshake, TLSClientHello, {'type':0x01})
bind_layers(TLSHandshake, TLSServerHello, {'type':0x02})
bind_layers(TLSHandshake, TLSCertificateList, {'type':0x0b})
bind_layers(TLSHandshake, TLSServerKeyExchange, {'type':0x0c})
bind_layers(TLSHandshake, TLSServerHelloDone, {'type':0x0e})
bind_layers(TLSHandshake, TLSClientKeyExchange, {'type':0x10})
bind_layers(TLSHandshake, TLSFinished, {'type':0x14})
# <---
bind_layers(TLSServerKeyExchange, TLSKexParamEncryptedPremasterSecret)
bind_layers(TLSClientKeyExchange, TLSKexParamEncryptedPremasterSecret)


bind_layers(TLSServerKeyExchange, TLSKexParamDH)
bind_layers(TLSClientKeyExchange, TLSKexParamDH)


# --> extensions
bind_layers(TLSExtension, TLSServerNameIndication, {'type': 0x0000})
bind_layers(TLSExtension, TLSExtMaxFragmentLength, {'type': 0x0001})
bind_layers(TLSExtension, TLSExtCertificateURL, {'type': 0x0002})
bind_layers(TLSExtension, TLSExtECPointsFormat, {'type': 0x000b})
bind_layers(TLSExtension, TLSExtEllipticCurves, {'type': 0x000a})
bind_layers(TLSExtension, TLSALPN, {'type': 0x0010})
# bind_layers(TLSExtension,Raw,{'type': 0x0023})
bind_layers(TLSExtension, TLSExtHeartbeat, {'type': 0x000f})
# <--


# DTLSRecord
bind_layers(DTLSRecord, DTLSHandshake, {'content_type':0x16})
bind_layers(DTLSHandshake, DTLSClientHello, {'type':0x01})


# SSLv2 
bind_layers(SSLv2Record, SSLv2ServerHello, {'content_type':0x04})
bind_layers(SSLv2Record, SSLv2ClientHello, {'content_type':0x01})
bind_layers(SSLv2Record, SSLv2ClientMasterKey, {'content_type':0x02})
