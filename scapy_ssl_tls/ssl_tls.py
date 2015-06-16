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

import ssl_tls_registry as registry
    
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

class StrConditionalField(ConditionalField):
    '''
    Base conditional field that is not restricted to pkt checks
    + allows conditional checks on the raw_stream 's'
    + allows conditional checks on the layers build value
    '''
    def _evalcond(self, pkt=None, s=None, val=None):
        return self.cond(pkt, s, val)
    
    def getfield(self, pkt, s):
        if self._evalcond(pkt,s):
            return self.fld.getfield(pkt,s)
        else:
            return s,None
        
    def addfield(self, pkt, s, val):
        if self._evalcond(pkt,s,val):
            return self.fld.addfield(pkt,s,val)
        else:
            return s

class PacketNoPadding(Packet):
    '''
    This type of packet does not contain padding or Raw data at the end
    '''
    def extract_padding(self, s):
        return '', s
    
class StackedLenPacket(Packet):
    ''' Allows stacked packets. Tries to chop layers by layer.length
    '''
    def do_dissect_payload(self, s):
        # prototype for this layer. only layers of same type can be stacked
        cls = self.guess_payload_class(s)
        cls_header_len = len(cls())
        # dissect potentially stacked sublayers.
        while len(s):
            # dissect raw_bytes s
            p = cls(s, _internal=1, _underlayer=self)
            s_len = len(s)
            try:
                # if there is a length field, chop the stream, add the payload
                # otherwise we'll consume the full length and return
                if p.length <= s_len:
                    p = cls(s[:cls_header_len+p.length], _internal=1, _underlayer=self)
                    s_len = cls_header_len+p.length
            except AttributeError, ae:
                pass
            self.add_payload(p)
            s = s[s_len:]  

class EnumStruct(object):
    def __init__(self, entries):
        entries = dict((v.replace(' ','_').upper(),k) for k,v in entries.iteritems())
        self.__dict__.update(entries)

TLS_VERSIONS = {
    # SSL
    0x0002:"SSL_2_0",
    0x0300:"SSL_3_0",
    # TLS
    0x0301:"TLS_1_0",
    0x0302:"TLS_1_1",
    0x0303:"TLS_1_2",
    # DTLS
    0x0100:"PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
    0xfeff:"DTLS_1_0",
    0xfefd:"DTLS_1_1",
    }
TLSVersion = EnumStruct(TLS_VERSIONS)

TLS_CONTENT_TYPES = registry.TLS_CONTENTTYPE_REGISTRY
TLSContentType = EnumStruct(TLS_CONTENT_TYPES)

TLS_HANDSHAKE_TYPES = registry.TLS_HANDSHAKETYPE_REGISTRY
TLSHandshakeType = EnumStruct(TLS_HANDSHAKE_TYPES)

TLS_EXTENSION_TYPES = registry.EXTENSIONTYPE_VALUES
TLS_EXTENSION_TYPES.update({0x3374:"next_protocol_negotiation"})    # manually add NPN as it is not in iana registry
TLSExtensionType = EnumStruct(TLS_EXTENSION_TYPES)

TLS_ALERT_LEVELS = {
    0x01: "warning",
    0x02: "fatal",
    0xff: "unknown", 
    }
TLSAlertLevel = EnumStruct(TLS_ALERT_LEVELS)

TLS_ALERT_DESCRIPTIONS = registry.TLS_ALERT_REGISTRY
TLSAlertDescription = EnumStruct(TLS_ALERT_DESCRIPTIONS)

TLS_EXT_MAX_FRAGMENT_LENGTH_ENUM = {
    0x01: 2 ** 9,
    0x02: 2 ** 10,
    0x03: 2 ** 11,
    0x04: 2 ** 12,
    0xff: 'unknown',
    }

TLS_CIPHER_SUITES = registry.TLS_CIPHER_SUITE_REGISTRY
# adding missing ciphers
TLS_CIPHER_SUITES.update({
    0x0060: 'RSA_EXPORT1024_WITH_RC4_56_MD5',
    0x0061: 'RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',
    0x0062: 'RSA_EXPORT1024_WITH_DES_CBC_SHA',
    0x0063: 'DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
    0x0064: 'RSA_EXPORT1024_WITH_RC4_56_SHA',
    0x0065: 'DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
    0x0066: 'DHE_DSS_WITH_RC4_128_SHA'})
TLSCipherSuite = EnumStruct(TLS_CIPHER_SUITES)

TLS_COMPRESSION_METHODS = registry.TLS_COMPRESSION_METHOD_IDENTIFIERS
TLSCompressionMethod = EnumStruct(TLS_COMPRESSION_METHODS)

TLS_CERT_CHAIN_TYPE = {
    0x00: 'individual_certs',
    0x01: 'pkipath',
    0xff: 'unknown',
    }
TLSCertChainType = EnumStruct(TLS_CERT_CHAIN_TYPE)

TLS_HEARTBEAT_MODE = registry.HEARTBEAT_MODES
TLSHeartbeatMode = EnumStruct(TLS_HEARTBEAT_MODE)

TLS_HEARTBEAT_MESSAGE_TYPE = registry.HEARTBEAT_MESSAGE_TYPES
TLSHeartbeatMessageType = EnumStruct(TLS_HEARTBEAT_MESSAGE_TYPE)

TLS_TYPE_BOOLEAN = {
    0x00: 'false',
    0x01: 'true',
    }
TLSTypeBoolean = EnumStruct(TLS_TYPE_BOOLEAN)

TLS_EC_POINT_FORMATS = registry.EC_POINT_FORMAT_REGISTRY
TLSEcPointFormat = EnumStruct(TLS_EC_POINT_FORMATS)
    
TLS_ELLIPTIC_CURVES = registry.EC_NAMED_CURVE_REGISTRY
TLSEllipticCurve = EnumStruct(TLS_ELLIPTIC_CURVES)

class TLSRecord(StackedLenPacket):
    name = "TLS Record"
    fields_desc = [ByteEnumField("content_type", TLSContentType.APPLICATION_DATA, TLS_CONTENT_TYPES),
                   XShortEnumField("version", TLSVersion.TLS_1_0, TLS_VERSIONS),
                   XLenField("length", None, fmt="!H"), ]
    
    def guess_payload_class(self, payload):
        ''' Sense for ciphertext
        '''
        cls = StackedLenPacket.guess_payload_class(self, payload)
        p = cls(payload, _internal=1, _underlayer=self)
        try:
            if cls == Raw().__class__ or p.length > len(payload) :
                # length does not fit len raw_bytes, assume its corrupt or encrypted
                cls = TLSCiphertext
        except AttributeError:
            # e.g. TLSChangeCipherSpec might land here
            pass
        return cls

class TLSHandshake(Packet):
    name = "TLS Handshake"
    fields_desc = [ByteEnumField("type", TLSHandshakeType.CLIENT_HELLO, TLS_HANDSHAKE_TYPES),
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
                   
                   StrConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"), lambda pkt,s,val: True if val else False),
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

                   StrConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"), lambda pkt,s,val: True if val else False),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length),
                   ]

class TLSSessionTicket(Packet):
    name = "TLS Session Ticket"
    fields_desc = [IntField("lifetime", 7200),
                   XFieldLenField("ticket_length", None, length_of="ticket", fmt="!H"),
                   StrLenField("ticket", '', length_from=lambda x:x.ticket_length),
                   ]     

class TLSHeartBeat(Packet):
    name = "TLS Extension HeartBeat"
    fields_desc = [ByteEnumField("type", TLSHeartbeatMessageType.HEARTBEAT_REQUEST, TLS_HEARTBEAT_MESSAGE_TYPE),
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
    
class TLSCertificate(PacketNoPadding):
    name = "TLS Certificate"
    fields_desc = [ XBLenField("length", None, length_of="data", fmt="!I", numbytes=3),
                    PacketLenField("data", None, x509.X509Cert, length_from=lambda x:x.length),]

class TLSCertificateList(Packet):
    name = "TLS Certificate List"
    fields_desc = [
                   XBLenField("length", None, length_of="certificates", fmt="!I", numbytes=3),
                   PacketListField("certificates", None, TLSCertificate, length_from=lambda x:x.length),
                  ]   

class TLSDecryptablePacket(Packet):

    explicit_iv_field = StrField("explicit_iv", "", fmt="H")
    mac_field = StrField("mac", "", fmt="H")
    padding_field = StrLenField("padding", "", length_from=lambda pkt:pkt.padding_len)
    padding_len_field = ConditionalField(XFieldLenField("padding_len", None, length_of="padding", fmt="B"), lambda pkt: True if pkt.padding != "" else False )
    decryptable_fields = [mac_field, padding_field, padding_len_field]

    def __init__(self, *args, **fields):
        try:
            self.tls_ctx = fields["ctx"]
            del(fields["ctx"])
            self.above_tls10 = self.tls_ctx.params.negotiated.version > TLSVersion.TLS_1_0
            if self.explicit_iv_field not in self.fields_desc and self.above_tls10:
                self.fields_desc.append(self.explicit_iv_field)
            for field in self.decryptable_fields:
                if field not in self.fields_desc:
                    self.fields_desc.append(field)
        except KeyError:
            self.tls_ctx = None
        Packet.__init__(self, *args, **fields)

    def pre_dissect(self, raw_bytes):
        data = raw_bytes
        if self.tls_ctx is not None:
            hash_size = self.tls_ctx.sec_params.mac_key_length
            iv_size = self.tls_ctx.sec_params.iv_length
            # CBC mode
            if self.tls_ctx.sec_params.negotiated_crypto_param["cipher"]["mode"] != None:
                try:
                    self.padding_len = ord(raw_bytes[-1])
                    self.padding = raw_bytes[-self.padding_len - 1:-1]
                    self.mac = raw_bytes[-self.padding_len - hash_size - 1:-self.padding_len - 1]
                    if self.above_tls10:
                        self.explicit_iv = raw_bytes[:iv_size]
                        data = raw_bytes[iv_size:-self.padding_len - hash_size - 1]
                    else:
                        data = raw_bytes[:-self.padding_len - hash_size - 1]
                except IndexError:
                    data = raw_bytes
            else:
                self.mac = raw_bytes[-hash_size:]
                data = raw_bytes[:-hash_size]
        # Return plaintext without mac and padding
        return data

class TLSPlaintext(TLSDecryptablePacket):
    name = "TLS Plaintext"
    fields_desc = [ StrField("data", None, fmt="H") ]

class TLSChangeCipherSpec(TLSDecryptablePacket):
    name = "TLS ChangeCipherSpec"
    fields_desc = [ StrField("message", '\x01', fmt="H") ]

class TLSAlert(TLSDecryptablePacket):
    name = "TLS Alert"
    fields_desc = [ ByteEnumField("level", TLSAlertLevel.WARNING, TLS_ALERT_LEVELS),
                    ByteEnumField("description", TLSAlertDescription.CLOSE_NOTIFY, TLS_ALERT_DESCRIPTIONS),
                  ]

class TLSCiphertext(Packet):
    name = "TLS Ciphertext"
    fields_desc = [ StrField("data", None, fmt="H") ]

class DTLSRecord(Packet):
    name = "DTLS Record"
    fields_desc = [ByteEnumField("content_type", TLSContentType.APPLICATION_DATA, TLS_CONTENT_TYPES),
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
                   
                   StrConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"), lambda pkt,s,val: True if val else False),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length),
                   ]   
    
SSLv2_CERTIFICATE_TYPES = { 0x01: 'x509' }
SSLv2CertificateType = EnumStruct(SSLv2_CERTIFICATE_TYPES)

class DTLSHelloVerify(Packet):
    name = "DTLS Hello Verify"
    fields_desc = [XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
                   XFieldLenField("cookie_length", None, length_of="cookie", fmt="B"),
                   StrLenField("cookie", '', length_from=lambda x:x.cookie_length),
                   ]
    
    
SSLv2_MESSAGE_TYPES = {
    0x01:'client_hello',
    0x04: 'server_hello',
    0x02: 'client_master_key',
    }
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

class TLSSocket(object):

    def __init__(self, socket, client=None, tls_ctx=None):
        if socket is not None:
            self._s = socket
        else:
            raise ValueError("Socket cannot be None")

        if client is None:
            self.client = self._is_listening(socket)
        else:
            self.client = client

        if tls_ctx is None:
            import ssl_tls_crypto as tlsc
            self.tls_ctx = tlsc.TLSSessionCtx(self.client)
        else:
            self.tls_ctx = tls_ctx

    def _is_listening(self, socket):
        import errno
        import socket
        try:
            is_listening = self._s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except socket.error as se:
            # OSX and BSDs do not support ENOPROTOOPT. Linux and Windows seem to
            if se.errno == errno.ENOPROTOOPT:
                raise RuntimeError("OS does not support SO_ACCEPTCONN, cannot determine socket state. Please supply an explicit client value (True for client, False for server)")
            else:
                raise
        return True if is_listening != 0 else False

    def __getattr__(self, attr):
        try:
            super(TLSSocket, self).__getattr__()
        except AttributeError:
            return getattr(self._s, attr)

    def sendall(self, pkt, timeout=2):
        prev_timeout = self._s.gettimeout()
        self._s.settimeout(timeout)
        self._s.sendall(str(pkt))
        self.tls_ctx.insert(pkt)
        self._s.settimeout(prev_timeout)

    def recvall(self, size=8192, timeout=0.5):
        resp = []
        prev_timeout = self._s.gettimeout()
        self._s.settimeout(timeout)
        while True:
            try:
                data = self._s.recv(size)
                if not data:
                    break
                resp.append(data)
            except socket.timeout:
                break
        self._s.settimeout(prev_timeout)
        records = TLS("".join(resp), ctx=self.tls_ctx)
        self.tls_ctx.insert(records)
        return records



# entry class
class SSL(Packet):
    '''
    COMPOUND CLASS for SSL
    '''
    name = "SSL/TLS"
    fields_desc = [PacketListField("records", None, TLSRecord)]

    def __init__(self, *args, **fields):
        try:
            self.tls_ctx = fields["ctx"]
            del(fields["ctx"])
        except KeyError:
            self.tls_ctx = None
        Packet.__init__(self, *args, **fields)

    @classmethod
    def from_records(cls, records):
        pkt_str = "".join(list(map(str, records)))
        return cls(pkt_str)

    def pre_dissect(self, raw_bytes):
        # figure out if we're UDP or TCP
        if self.underlayer is not None and self.underlayer.haslayer(UDP):
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

    def _get_encrypted_payload(self, record):
        encrypted_payload = None
        decrypted_type = None
        # Application data
        if record.haslayer(TLSCiphertext):
            encrypted_payload = record[TLSCiphertext].data
            decrypted_type = TLSPlaintext
        # Handshake with no recognized upper layer = TLSFinished
        elif (record.haslayer(TLSHandshake) and record[TLSHandshake].payload.name == Raw.name):
            encrypted_payload = str(record.payload)
            decrypted_type = TLSHandshake
        # Do not decrypt cleartext Alerts and CCS
        elif record.haslayer(TLSAlert) and record.length != 0x2:
            encrypted_payload = str(record.payload)
            decrypted_type = TLSAlert
        elif record.haslayer(TLSChangeCipherSpec) and record.length != 0x1:
            encrypted_payload = str(record.payload)
            decrypted_type = TLSChangeCipherSpec
        return (encrypted_payload, decrypted_type)

    def post_dissect(self, s):
        if self.tls_ctx is not None:
            for record in self.records:
                encrypted_payload, layer = self._get_encrypted_payload(record)
                if encrypted_payload is not None:
                    try:
                        if self.tls_ctx.client:
                            cleartext = self.tls_ctx.crypto.server.dec.decrypt(encrypted_payload)
                        else:
                            cleartext = self.tls_ctx.crypto.client.dec.decrypt(encrypted_payload)
                        pkt = layer(cleartext, ctx=self.tls_ctx)
                        record[self.guessed_next_layer].payload = pkt
                    # Decryption failed, raise error otherwise we'll be in inconsistent state with sender
                    except ValueError as ve:
                        raise ValueError("Decryption failed: %s" % ve)
        return s 

TLS = SSL

cleartext_handler = { TLSPlaintext: lambda pkt, tls_ctx: (TLSContentType.APPLICATION_DATA, pkt[TLSPlaintext].data),
                      TLSFinished: lambda pkt, tls_ctx: (TLSContentType.HANDSHAKE, str(TLSHandshake(type=TLSHandshakeType.FINISHED)/tls_ctx.get_verify_data())),
                      TLSChangeCipherSpec: lambda pkt, tls_ctx: (TLSContentType.CHANGE_CIPHER_SPEC, str(pkt)),
                      TLSAlert: lambda pkt, tls_ctx: (TLSContentType.ALERT, str(pkt)) }

def to_raw(pkt, tls_ctx, include_record=True, compress_hook=None, pre_encrypt_hook=None, encrypt_hook=None):
    import ssl_tls_crypto as tlsc

    if tls_ctx is None:
        raise ValueError("A valid TLS session context must be provided")
    comp_method = tls_ctx.compression.method

    content_type, data = None, None
    for tls_proto, handler in cleartext_handler.iteritems():
        if pkt.haslayer(tls_proto):
            content_type, data = handler(pkt[tls_proto], tls_ctx)
    if content_type is None and data is None:
        raise KeyError("Unhandled encryption for TLS protocol: %s" % tls_proto)

    if compress_hook is not None:
        post_compress_data = compress_hook(comp_method, data)
    else:
        post_compress_data = comp_method.compress(data)

    if pre_encrypt_hook is not None:
        cleartext, mac, padding = pre_encrypt_hook(post_compress_data)
        crypto_container = tlsc.CryptoContainer(tls_ctx, cleartext, content_type)
        crypto_container.mac = mac
        crypto_container.padding = padding
    else:
        cleartext = post_compress_data
        crypto_container = tlsc.CryptoContainer(tls_ctx, cleartext, content_type)
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
bind_layers(TLSRecord, TLSChangeCipherSpec, {'content_type':TLSContentType.CHANGE_CIPHER_SPEC})
bind_layers(TLSRecord, TLSCiphertext, {"content_type":TLSContentType.APPLICATION_DATA})
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
bind_layers(TLSHandshake, TLSSessionTicket, {'type':TLSHandshakeType.NEWSESSIONTICKET})
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
bind_layers(TLSExtension, TLSExtSessionTicketTLS, {'type':TLSExtensionType.SESSIONTICKET_TLS})
bind_layers(TLSExtension, TLSExtRenegotiationInfo, {'type':TLSExtensionType.RENEGOTIATION_INFO})
# <--

# DTLSRecord
bind_layers(DTLSRecord, DTLSHandshake, {'content_type':TLSContentType.HANDSHAKE})
bind_layers(DTLSHandshake, DTLSClientHello, {'type':TLSHandshakeType.CLIENT_HELLO})

# SSLv2 
bind_layers(SSLv2Record, SSLv2ServerHello, {'content_type':0x04})
bind_layers(SSLv2Record, SSLv2ClientHello, {'content_type':0x01})
bind_layers(SSLv2Record, SSLv2ClientMasterKey, {'content_type':0x02})
