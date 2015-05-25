#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html

import os
import time

from scapy.packet import bind_layers, NoPayload, Packet, Raw
from scapy.fields import *
from scapy.layers.inet import TCP, UDP
from scapy.layers import x509


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

class PacketNoPadding(Packet):
    '''
    This type of packet does not contain padding or Raw data at the end
    '''
    def extract_padding(self, s):
        return '', s
    
class EnumStruct(object):
    def __init__(self, entries):
        entries = dict((v.upper(),k) for k,v in entries.iteritems())
        self.__dict__.update(entries)

TLS_VERSIONS = {  0x0002:"SSL_2_0",
                  0x0300:"SSL_3_0",
                  0x0301:"TLS_1_0",
                  0x0302:"TLS_1_1",
                  0x0303:"TLS_1_2",
                  
                  0x0100:"PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
                  0xfeff:"DTLS_1_0",
                  0xfefd:"DTLS_1_1",
                  }
TLSVersion = EnumStruct(TLS_VERSIONS)

TLS_CONTENT_TYPES = {0x14:"change_cipher_spec",
                        0x15:"alert",
                        0x16:"handshake",
                        0x17:"application_data",
                        0x18:"heartbeat",
                        0xff:"unknown"}
TLSContentType = EnumStruct(TLS_CONTENT_TYPES)

TLS_HANDSHAKE_TYPES = {0x00:"hello_request",
                        0x01:"client_hello",
                        0x02:"server_hello",
                        0x04:"new_session_ticket",
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
TLSHandshakeType = EnumStruct(TLS_HANDSHAKE_TYPES)

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
                       0xff01:"renegotiation_info",
                       }
TLSExtensionType = EnumStruct(TLS_EXTENSION_TYPES)

TLS_ALERT_LEVELS = { 0x01: "warning",
                     0x02: "fatal",
                     0xff: "unknown", }
TLSAlertLevel = EnumStruct(TLS_ALERT_LEVELS)

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
TLSAlertDescription = EnumStruct(TLS_ALERT_DESCRIPTIONS)

TLS_EXT_MAX_FRAGMENT_LENGTH_ENUM = {
                                    0x01: 2 ** 9,
                                    0x02: 2 ** 10,
                                    0x03: 2 ** 11,
                                    0x04: 2 ** 12,
                                    0xff: 'unknown',
                                    }


TLS_CIPHER_SUITES = {
                        0x0000: 'NULL_WITH_NULL_NULL',
                        0x0001: 'RSA_WITH_NULL_MD5',
                        0x0002: 'RSA_WITH_NULL_SHA1',
                        0x0003: 'RSA_EXPORT_WITH_RC4_40_MD5',
                        0x0004: 'RSA_WITH_RC4_128_MD5',
                        0x0005: 'RSA_WITH_RC4_128_SHA',
                        0x0006: 'RSA_EXPORT_WITH_RC2_CBC_40_MD5',
                        0x0007: 'RSA_WITH_IDEA_CBC_SHA',
                        0x0008: 'RSA_EXPORT_WITH_DES40_CBC_SHA',
                        0x0009: 'RSA_WITH_DES_CBC_SHA',
                        0x000a: 'RSA_WITH_3DES_EDE_CBC_SHA',
                        0x0011: 'DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
                        0x0012: 'DHE_DSS_WITH_DES_CBC_SHA',
                        0x0013: 'DHE_DSS_WITH_3DES_EDE_CBC_SHA',
                        0x0014: 'DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
                        0x0015: 'DHE_RSA_WITH_DES_CBC_SHA',
                        0x0016: 'DHE_RSA_WITH_3DES_EDE_CBC_SHA',
                        0x002f: 'RSA_WITH_AES_128_CBC_SHA',
                        0x0032: 'DHE_DSS_WITH_AES_128_CBC_SHA',
                        0x0033: 'DHE_RSA_WITH_AES_128_CBC_SHA',
                        0x0035: 'RSA_WITH_AES_256_CBC_SHA',
                        0x0038: 'DHE_DSS_WITH_AES_256_CBC_SHA',
                        0x0039: 'DHE_RSA_WITH_AES_256_CBC_SHA',
                        0x003b: 'RSA_WITH_NULL_SHA256',
                        0x0060: 'RSA_EXPORT1024_WITH_RC4_56_MD5',
                        0x0061: 'RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',
                        0x0062: 'RSA_EXPORT1024_WITH_DES_CBC_SHA',
                        0x0063: 'DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
                        0x0064: 'RSA_EXPORT1024_WITH_RC4_56_SHA',
                        0x0065: 'DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
                        0x0066: 'DHE_DSS_WITH_RC4_128_SHA',
                        0x0084: 'RSA_WITH_CAMELLIA_256_CBC_SHA',
                        0x0087: 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
                        0x0088: 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
                        0x5600: 'TLS_FALLBACK_SCSV',
                        0xc005: 'ECDH_ECDSA_WITH_AES_256_CBC_SHA',
                        0xc00a: 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
                        0xc00f: 'ECDH_RSA_WITH_AES_256_CBC_SHA',
                        0xc014: 'ECDHE_RSA_WITH_AES_256_CBC_SHA',
                        0xc021: 'SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
                        0xc022: 'SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
}
TLSCipherSuite = EnumStruct(TLS_CIPHER_SUITES)

TLS_COMPRESSION_METHODS = {
                           0x00: 'null',
                           0x01: 'deflate',
                           }
TLSCompressionMethod = EnumStruct(TLS_COMPRESSION_METHODS)

TLS_CERT_CHAIN_TYPE = { 0x00: 'individual_certs',
                    0x01: 'pkipath',
                    0xff: 'unknown'}
TLSCertChainType = EnumStruct(TLS_CERT_CHAIN_TYPE)

TLS_HEARTBEAT_MODE = { 0x01: 'peer_allowed_to_send',
                       0x02: 'peer_not_allowed_to_send',
                       0xff: 'unknown'}
TLSHeartbeatMode = EnumStruct(TLS_HEARTBEAT_MODE)

TLS_TYPE_BOOLEAN = {0x00: 'false',
                    0x01: 'true'}
TLSTypeBoolean = EnumStruct(TLS_TYPE_BOOLEAN)

TLS_EC_POINT_FORMATS = {0x00:'uncompressed',
                            0x01:'ansiX962_compressed_prime',
                            0x02:'ansiX962_compressed_char2'}
TLSEcPointFormat = EnumStruct(TLS_EC_POINT_FORMATS)
    
TLS_ELLIPTIC_CURVES = {0x000e:'sect571r1',}
TLSEllipticCurve = EnumStruct(TLS_ELLIPTIC_CURVES)

class TLSRecord(Packet):
    name = "TLS Record"
    fields_desc = [ByteEnumField("content_type", TLSContentType.UNKNOWN, TLS_CONTENT_TYPES),
                   XShortEnumField("version", TLSVersion.TLS_1_0, TLS_VERSIONS),
                   XLenField("length", None, fmt="!H"), ]
    
    def do_dissect_payload(self, s):
        # this is basically what scapy does + sensing for ciphertexts
        cls = self.guess_payload_class(s)
        p = cls(s, _internal=1, _underlayer=self)
        # ------------->
        # check sublayer sanity to distingiush wrong layers from Ciphertext
        try:
            # Raw sublayers to TLSRecords are most likely TLSCipherText 
            # Bogus layers have invalid length fields. most likely an encrypted Handshake
            if cls == Raw().__class__ or p.length > len(s) :
                # length does not fit len raw_bytes, assume its corrupt or encrypted
                p = TLSCiphertext(s, _internal=1, _underlayer=self)
        except AttributeError, ae:
            # e.g. TLSChangeCipherSpec might land here
            pass
        # <--------------
        self.add_payload(p)

class TLSHandshake(Packet):
    name = "TLS Handshake"
    fields_desc = [ByteEnumField("type", TLSHandshakeType.UNKNOWN, TLS_HANDSHAKE_TYPES),
                   XBLenField("length", None, fmt="!I", numbytes=3), ]

class TLSServerName(PacketNoPadding):
    name = "TLS Servername"
    fields_desc = [ByteEnumField("type", 0x00, {0x00:"host"}),
                  XFieldLenField("length", None, length_of="data", fmt="H"),
                  StrLenField("data", "", length_from=lambda x:x.length),
                  ]
    
class TLSExtServerNameIndication(PacketNoPadding):
    name = "TLS Extension Servername Indication"
    fields_desc = [XFieldLenField("length", None, length_of="server_names", fmt="H"),
                   PacketListField("server_names", None, TLSServerName, length_from=lambda x:x.length),
                  ]
    
#https://tools.ietf.org/html/rfc7301
class TLSALPNProtocol(PacketNoPadding):
    name = "TLS ALPN Protocol"
    fields_desc = [
                  XFieldLenField("length", None, length_of="data", fmt="B"),
                  StrLenField("data", "", length_from=lambda x:x.length),
                  ]
    
class TLSExtALPN(PacketNoPadding):
    name = "TLS Extension Application-Layer Protocol Negotiation"
    fields_desc = [XFieldLenField("length", None, length_of="protocol_name_list", fmt="H"),
                   PacketListField("protocol_name_list", None, TLSALPNProtocol, length_from=lambda x:x.length),
                  ]

class TLSExtension(Packet):
    name = "TLS Extension"
    fields_desc = [XShortEnumField("type", TLSExtensionType.SERVER_NAME, TLS_EXTENSION_TYPES),
                   XLenField("length", None, fmt="!H"),
                  ]

# https://www.ietf.org/rfc/rfc3546.txt
class TLSExtMaxFragmentLength(PacketNoPadding):
    name = "TLS Extension Max Fragment Length"
    fields_desc = [ByteEnumField("fragment_length", 0xff, TLS_EXT_MAX_FRAGMENT_LENGTH_ENUM)]

class TLSURLAndOptionalHash(Packet):
    name = "TLS Extension Certificate URL/Hash"
    fields_desc = [XFieldLenField("url_length", None, length_of="url", fmt="H"),
                  StrLenField("url", "", length_from=lambda x:x.url_length),
                  ByteEnumField("hash_present", TLSTypeBoolean.FALSE, TLS_TYPE_BOOLEAN),
                  StrLenField("sha1hash", "", length_from=lambda x:20 if x.hash_present else 0),  # opaque SHA1Hash[20];
                  ]
    
class TLSExtCertificateURL(PacketNoPadding):
    name = "TLS Extension Certificate URL"
    fields_desc = [ByteEnumField("type", TLSCertChainType.INDIVIDUAL_CERTS, TLS_CERT_CHAIN_TYPE),
                   XFieldLenField("length", None, length_of="certificate_urls", fmt="H"),
                   PacketListField("certificate_urls", None, TLSURLAndOptionalHash, length_from=lambda x:x.length)
                   ]
    
class TLSExtECPointsFormat(PacketNoPadding):
    name = "TLS Extension EC Points Format"
    fields_desc = [
                   XFieldLenField("length", None, length_of="ec_point_formats", fmt="B"),
                   FieldListField("ec_point_formats", None, ByteEnumField("ec_point_format", None, TLS_EC_POINT_FORMATS), length_from=lambda x:x.length),
                  ]

class TLSExtEllipticCurves(PacketNoPadding):
    name = "TLS Extension Elliptic Curves"
    fields_desc = [
                   XFieldLenField("length", None, length_of="elliptic_curves", fmt="H"),
                   FieldListField("elliptic_curves", None, ShortEnumField("elliptic_curve", None, TLS_ELLIPTIC_CURVES), length_from=lambda x:x.length),
                  ]
    
class TLSExtHeartbeat(PacketNoPadding):
    name = "TLS Extension HeartBeat"
    fields_desc = [ByteEnumField("mode", TLSHeartbeatMode.PEER_NOT_ALLOWED_TO_SEND, TLS_HEARTBEAT_MODE)]

class TLSExtSessionTicketTLS(PacketNoPadding):
    name = "TLS Extension SessionTicket TLS"
    fields_desc = [StrLenField("data", '', length_from=lambda x:x.underlayer.length),] 
    
class TLSExtRenegotiationInfo(PacketNoPadding):
    name = "TLS Extension Renegotiation Info"
    fields_desc = [XFieldLenField("length", None, length_of="data", fmt="B"),
                   StrLenField("data", '', length_from=lambda x:x.length),] 

class TLSHelloRequest(Packet):
    name = "TLS Hello Request"
    fields_desc = []

class TLSClientHello(Packet):
    name = "TLS Client Hello"
    fields_desc = [XShortEnumField("version", TLSVersion.TLS_1_0, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
    
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   FieldListField("cipher_suites", [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA], XShortEnumField("cipher", None, TLS_CIPHER_SUITES), length_from=lambda x:x.cipher_suites_length),
                   
                   XFieldLenField("compression_methods_length", None, length_of="compression_methods", fmt="B"),
                   FieldListField("compression_methods", [TLSCompressionMethod.NULL], ByteEnumField("compression", None, TLS_COMPRESSION_METHODS), length_from=lambda x:x.compression_methods_length),
                   
                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length),
                   ] 

    
class TLSServerHello(Packet):
    name = "TLS Server Hello"
    fields_desc = [XShortEnumField("version", TLSVersion.TLS_1_0, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),

                   XShortEnumField("cipher_suite", TLSCipherSuite.NULL_WITH_NULL_NULL, TLS_CIPHER_SUITES),
                   ByteEnumField("compression_method", TLSCompressionMethod.NULL, TLS_COMPRESSION_METHODS),

                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"), 
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length), 
                   ]

class TLSSessionTicket(Packet):
    name = "TLS Session Ticket"
    fields_desc = [IntField("lifetime", 7200),
                   XFieldLenField("ticket_length", None, length_of="ticket", fmt="!H"),
                   StrLenField("ticket", '', length_from=lambda x:x.ticket_length),
                   ]     

class TLSAlert(Packet):
    name = "TLS Alert"
    fields_desc = [ByteEnumField("level", TLSAlertLevel.UNKNOWN, TLS_ALERT_LEVELS),
                  ByteEnumField("description", TLSAlertDescription.UNKNOWN, TLS_ALERT_DESCRIPTIONS),
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

class TLSKexParamDH(Packet):
    name = "TLS Kex DH Params"
    fields_desc = [ StrLenField("data", None) ]

class TLSFinished(Packet):
    name = "TLS Handshake Finished"
    fields_desc = [ StrLenField("data", None) ]

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
                    PacketLenField("data", None, x509.X509Cert, length_from=lambda x:x.length),]

class TLSCertificateList(Packet):
    name = "TLS Certificate List"
    fields_desc = [
                   XBLenField("length", None, length_of="certificates", fmt="!I", numbytes=3),
                   PacketListField("certificates", None, TLSCertificate, length_from=lambda x:x.length),
                  ]   

class TLSChangeCipherSpec(Packet):
    name = "TLS ChangeCipherSpec"
    fields_desc = [ StrField("message", '\x01', fmt="H")]

class TLSCiphertext(Packet):
    name = "TLS Ciphertext"
    fields_desc = [ StrField("data", None, fmt="H")]

class TLSPlaintext(Packet):
    name = "TLS Plaintext"
    fields_desc = [ StrField("data", None, fmt="H") ]

class DTLSRecord(Packet):
    name = "DTLS Record"
    fields_desc = [ByteEnumField("content_type", TLSContentType.UNKNOWN, TLS_CONTENT_TYPES),
                   XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
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
    fields_desc = [XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
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
                   
                   ConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"), lambda pkt: True if pkt.extensions != [] else False),
                   ConditionalField(PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extension_length), lambda pkt: True if pkt.extensions != [] else False)
                   ]   
    
SSLv2_CERTIFICATE_TYPES = { 0x01: 'x509'}
SSLv2CertificateType = EnumStruct(SSLv2_CERTIFICATE_TYPES)

class DTLSHelloVerify(Packet):
    name = "DTLS Hello Verify"
    fields_desc = [XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
                   XFieldLenField("cookie_length", None, length_of="cookie", fmt="B"),
                   StrLenField("cookie", '', length_from=lambda x:x.cookie_length),
                   ]
    
    
SSLv2_MESSAGE_TYPES = {0x01:'client_hello',
                     0x04: 'server_hello',
                     0x02: 'client_master_key'}
SSLv2MessageType = EnumStruct(SSLv2_MESSAGE_TYPES)

SSLv2_CIPHER_SUITES = {
                        0x10080: 'RC4_128_WITH_MD5',
                        0x20080: 'RC4_128_EXPORT40_WITH_MD5',
                        0x40080: 'RC2_CBC_128_CBC_WITH_MD5',
                        0x50080: 'IDEA_128_CBC_WITH_MD5',
                        0x60040: 'DES_64_CBC_WITH_MD5',
                        0x700c0: 'DES_192_EDE3_CBC_WITH_MD5',
                        0x80080: 'RC4_64_WITH_MD5',
}

SSLv2CipherSuite = EnumStruct(SSLv2_CIPHER_SUITES)

class SSLv2Record(Packet):
    name = "SSLv2 Record"
    fields_desc = [XBLenField("length", None, fmt="!H", adjust_i2m=lambda pkt, x: x + 0x8000 + 1, adjust_m2i=lambda pkt, x:x - 0x8000),  # length=halfbyte+byte with MSB(high(1stbyte)) =1 || +1 for lengt(content_type)
                   ByteEnumField("content_type", 0xff, SSLv2_MESSAGE_TYPES),
                   ]

class SSLv2ClientHello(Packet):
    name = "SSLv2 Client Hello"
    fields_desc = [
                   XShortEnumField("version", TLSVersion.SSL_2_0, TLS_VERSIONS),

                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="H"),
                   XFieldLenField("challenge_length", None, length_of="challenge", fmt="H"),
                   
                   FieldListField("cipher_suites", None, XBEnumField("cipher", None, SSLv2_CIPHER_SUITES, fmt="!I", numbytes=3), length_from=lambda x:x.cipher_suites_length),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
                   StrLenField("challenge", '', length_from=lambda x:x.challenge_length),
                   ]

class SSLv2ServerHello(Packet):
    name = "SSLv2 Server Hello"
    fields_desc = [
                   ByteEnumField("session_id_hit", TLSTypeBoolean.FALSE, TLS_TYPE_BOOLEAN),
                   ByteEnumField("certificate_type", SSLv2CertificateType.X509, SSLv2_CERTIFICATE_TYPES),
                   XShortEnumField("version", TLSVersion.SSL_2_0, TLS_VERSIONS),

                   XFieldLenField("certificate_length", None, length_of="certificates", fmt="H"),
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   XFieldLenField("connection_id_length", None, length_of="connection_id", fmt="H"),
                   
                   StrLenField("certificates", '', length_from=lambda x:x.certificates_length),
                   FieldListField("cipher_suites", None, XBEnumField("cipher", None, SSLv2_CIPHER_SUITES, fmt="!I", numbytes=3), length_from=lambda x:x.cipher_suites_length),
                   StrLenField("connection_id", '', length_from=lambda x:x.connection_id_length),
                   ]

class SSLv2ClientMasterKey(Packet):
    name = "SSLv2 Client Master Key"
    fields_desc = [
                   XBEnumField("cipher_suite", SSLv2CipherSuite.RC4_128_WITH_MD5, SSLv2_CIPHER_SUITES, fmt="!I", numbytes=3),  # fixme: 3byte wide

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

    @classmethod
    def from_records(cls, records):
        pkt_str = "".join(list(map(str, records)))
        return cls(pkt_str)

    def pre_dissect(self, raw_bytes):
        # figure out if we're UDP or TCP
        if self.underlayer and self.underlayer.haslayer(UDP):
            self.guessed_next_layer = DTLSRecord
        elif ord(raw_bytes[0]) & 0x80:
            self.guessed_next_layer = SSLv2Record
        else:
            self.guessed_next_layer = TLSRecord
        self.fields_desc = [PacketListField("records", None, self.guessed_next_layer)]
        return raw_bytes

    def do_dissect(self, raw_bytes):
        pos = 0
        record = self.guessed_next_layer  # FIXME: detect DTLS
        record_header_len = len(record())

        records = []
        # Consume all bytes passed to us by the underlayer. We're expecting no
        # further payload on top of us. If there is additional data on top of our layer
        # We will incorrectly parse it
        while pos < len(raw_bytes)-record_header_len:   
            payload_len = record(raw_bytes[pos:pos+record_header_len]).length
            payload = record(raw_bytes[pos:pos+record_header_len+payload_len])
            # Populate our list of found records
            records.append(payload)
            # Move to the next record
            pos += (record_header_len + payload.length)
        self.fields["records"] = records
        # This will always be empty (equivalent to returning "")
        return raw_bytes[pos:]

TLS = SSL

cleartext_handler = { TLSPlaintext: lambda pkt, tls_ctx, client: (TLSContentType.APPLICATION_DATA, pkt.data),
                      TLSFinished: lambda pkt, tls_ctx, client: (TLSContentType.HANDSHAKE, str(TLSHandshake(type=TLSHandshakeType.FINISHED)/tls_ctx.get_verify_data())),
                      TLSChangeCipherSpec: lambda pkt, tls_ctx, client: (TLSContentType.CHANGE_CIPHER_SPEC, str(pkt)),
                      TLSAlert: lambda pkt, tls_ctx, client: (TLSContentType.ALERT, str(pkt)) }

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

def get_individual_layers(pkt):
    """ Returns all individual layers
    TLSRecord()/TLSHandshake()/TLSClientHello() will become [TLSRecord, TLSHandshake, TLSClientHello]
    """
    pkt = copy.deepcopy(pkt)
    # If we have a PacketListField, access it's records
    try:
        layers = pkt.records
    # Otherwise handle normally
    except AttributeError:
        layers = [pkt]
    for layer in layers:
        while layer.payload:
            current_layer = copy.deepcopy(layer)
            current_layer.payload = NoPayload()
            yield current_layer
            layer = layer.payload
        yield layer

def get_all_tls_layers(pkt, layer_type=TLSRecord, appender=lambda x: x):
    """ Returns all TLS layers (not scapy layers!) within a packet, 
    stripping the upper layers TLSRecord()/TLSHandshake()/TLSRecord()/TLSAlert()
    will become [TLSRecord/TLSHandshake, TLSRecord/TLSAlert]
    By default, this will return all TLSRecords
    """
    record = None
    for layer in get_individual_layers(pkt):
        if layer.name == layer_type.name:
            if record is not None:
                yield record
            record = layer
        else:
            if record is not None:
                layer = appender(layer)
                if layer is not None:
                    record /= layer
    # Yield the last calculated record if there is one
    if record is not None:
        yield record

# Alias function for consistancy
def get_all_tls_records(pkt):
    # yield from not in python 2.7
    # yield from get_all_tls_layers(pkt)
    for record in get_all_tls_layers(pkt):
        yield record
 
def get_all_tls_handshakes(pkt):
    # yield from get_all_tls_layers(pkt, TLSHandshake, lambda x: x if x.name != TLSRecord.name else None)
    for handshake in get_all_tls_layers(pkt, TLSHandshake, lambda x: x if x.name != TLSRecord.name else None):
        yield handshake

def get_all_layers(pkt, layer_type=TLSRecord):
    """ Returns all layer types within a packet, without stripping
    the upper layers. For example TLSRecord()/TLSHandshake()/TLSRecord()/TLSAlert() will become
    [TLSRecord/TLSHandshake/TLSRecord/TLSAlert, TLSRecord/TLSAlert]
    """
    i = 1
    while True:
        layer = pkt.getlayer(layer_type, nb=i)
        if layer is not None:
            yield layer
            i += 1
        else:
            break

# bind magic
bind_layers(TCP, SSL, dport=443)
bind_layers(TCP, SSL, sport=443)
bind_layers(UDP, SSL, dport=4433)
bind_layers(UDP, SSL, sport=4433)

# TLSRecord
bind_layers(TLSRecord, TLSChangeCipherSpec, {'content_type':TLSContentType.CHANGE_CIPHER_SPEC})
bind_layers(TLSRecord, TLSHeartBeat, {'content_type':TLSContentType.HEARTBEAT})
bind_layers(TLSRecord, TLSAlert, {'content_type':TLSContentType.ALERT})

bind_layers(TLSRecord, TLSHandshake, {'content_type':TLSContentType.HANDSHAKE})

# --> handshake proto
bind_layers(TLSHandshake, TLSHelloRequest, {'type':TLSHandshakeType.HELLO_REQUEST})
bind_layers(TLSHandshake, TLSClientHello, {'type':TLSHandshakeType.CLIENT_HELLO})
bind_layers(TLSHandshake, TLSServerHello, {'type':TLSHandshakeType.SERVER_HELLO})
bind_layers(TLSHandshake, TLSCertificateList, {'type':TLSHandshakeType.CERTIFICATE})
bind_layers(TLSHandshake, TLSServerKeyExchange, {'type':TLSHandshakeType.SERVER_KEY_EXCHANGE})
bind_layers(TLSHandshake, TLSServerHelloDone, {'type':TLSHandshakeType.SERVER_HELLO_DONE})
bind_layers(TLSHandshake, TLSClientKeyExchange, {'type':TLSHandshakeType.CLIENT_KEY_EXCHANGE})
bind_layers(TLSHandshake, TLSFinished, {'type':TLSHandshakeType.FINISHED})
bind_layers(TLSHandshake, TLSSessionTicket, {'type':TLSHandshakeType.NEW_SESSION_TICKET})
# <---


bind_layers(TLSServerKeyExchange, TLSKexParamDH)
bind_layers(TLSClientKeyExchange, TLSKexParamDH)

# --> extensions
bind_layers(TLSExtension, TLSExtServerNameIndication, {'type': TLSExtensionType.SERVER_NAME})
bind_layers(TLSExtension, TLSExtMaxFragmentLength, {'type': TLSExtensionType.MAX_FRAGMENT_LENGTH})
bind_layers(TLSExtension, TLSExtCertificateURL, {'type': TLSExtensionType.CLIENT_CERTIFICATE_URL})
bind_layers(TLSExtension, TLSExtECPointsFormat, {'type': TLSExtensionType.EC_POINT_FORMATS})
bind_layers(TLSExtension, TLSExtEllipticCurves, {'type': TLSExtensionType.ELLIPTIC_CURVES})
bind_layers(TLSExtension, TLSExtALPN, {'type': TLSExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION})
# bind_layers(TLSExtension,Raw,{'type': 0x0023})
bind_layers(TLSExtension, TLSExtHeartbeat, {'type': TLSExtensionType.HEARTBEAT})
bind_layers(TLSExtension, TLSExtSessionTicketTLS, {'type':TLSExtensionType.SESSION_TICKET_TLS})
bind_layers(TLSExtension, TLSExtRenegotiationInfo, {'type':TLSExtensionType.RENEGOTIATION_INFO})
# <--

# DTLSRecord
bind_layers(DTLSRecord, DTLSHandshake, {'content_type':TLSContentType.HANDSHAKE})
bind_layers(DTLSHandshake, DTLSClientHello, {'type':TLSHandshakeType.CLIENT_HELLO})

# SSLv2 
bind_layers(SSLv2Record, SSLv2ServerHello, {'content_type':0x04})
bind_layers(SSLv2Record, SSLv2ClientHello, {'content_type':0x01})
bind_layers(SSLv2Record, SSLv2ClientMasterKey, {'content_type':0x02})
