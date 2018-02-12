#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : <github.com/tintinweb/scapy-ssl_tls>

from scapy.packet import bind_layers, Packet, Raw
from scapy.fields import *
from scapy.layers.inet import TCP, UDP
from scapy.layers import x509


import ssl_tls_registry as registry


class BLenField(LenField):

    def __init__(
            self,
            name,
            default,
            fmt="I",
            adjust_i2m=lambda pkt,
            x: x,
            numbytes=None,
            length_of=None,
            count_of=None,
            adjust_m2i=lambda pkt,
            x: x):
        LenField.__init__(self, name, default, fmt)
        self.name = name
        self.adjust_i2m = adjust_i2m
        self.adjust_m2i = adjust_m2i
        self.numbytes = numbytes
        self.length_of = length_of
        self.count_of = count_of

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
        return s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, upack_data)[0])

    def i2m(self, pkt, x):
        if x is None:
            if not (self.length_of or self.count_of):
                x = len(pkt.payload)
            elif self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                x = fld.i2len(pkt, fval)
            else:
                fld, fval = pkt.getfield_and_val(self.count_of)
                x = fld.i2count(pkt, fval)
        return self.adjust_i2m(pkt, x)

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

        return s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, upack_data)[0])

    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return lhex(x)


class XBEnumField(BEnumField):

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class ReprFieldListField(FieldListField):

    """ Human Readable FieldListField for Enum type list entries """

    def i2repr(self, pkt, x):
        return self.field.i2repr(pkt, x)


class StrConditionalField(ConditionalField):

    """
    Base conditional field that is not restricted to pkt checks
    + allows conditional checks on the raw_stream 's'
    + allows conditional checks on the layers build value
    """

    def _evalcond(self, pkt=None, s=None, val=None):
        return self.cond(pkt, s, val)

    def getfield(self, pkt, s):
        if self._evalcond(pkt, s):
            return self.fld.getfield(pkt, s)
        else:
            return s, None

    def addfield(self, pkt, s, val):
        if self._evalcond(pkt, s, val):
            return self.fld.addfield(pkt, s, val)
        else:
            return s


class PacketNoPayload(Packet):

    """
    This type of packet has no payload/sub-layer (typically used for PacketListFields or leaf layers)
    """

    def extract_padding(self, s):
        return '', s


class PacketLengthFieldPayload(Packet):
    """
    This type of packet provides only up to self.length bytes to the next layer (payload)
    Applicable when last field is .length and the length describes the next-layer length in bytes
    Behaves like Packet.extract_padding if self.length is not available to make this Packet type work with all Packets
    """

    def extract_padding(self, s):
        if not hasattr(self, 'length'):
            return Packet.extract_padding(self, s)
        pay = s[:self.length]
        pad = s[self.length:]
        return pay, pad


class StackedLenPacket(Packet):
    """ Allows stacked packets. Tries to chop layers by layer.length
    """
    def __init__(self, *args, **fields):
        self.tls_ctx = fields.pop("ctx", None)
        Packet.__init__(self, *args, **fields)

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
                    p = cls(s[:cls_header_len + p.length], _internal=1, _underlayer=self)
                    s_len = cls_header_len + p.length
            except AttributeError:
                pass
            self.add_payload(p)
            s = s[s_len:]


class TypedPacketListField(PacketListField):
    """
    This type of field allows the created packet to be aware of whom created it. This is useful
    when a field of a packet needs to be aware of the packet type. For example, if an extension needs
    to know in which context it has been called, such a context can be provided in the type_ field.
    This is specifically used to handle the Key Share extension in TLS 1.3, where the parsing semantics
    change depending on which handshake packet type has defined the Key Share.
    """
    def __init__(self, name, default, cls, count_from=None, length_from=None, type_=None):
        self.type_ = type_
        PacketListField.__init__(self, name, default, cls, count_from=None, length_from=None)

    def m2i(self, pkt, m):
        return self.cls(m, type_=self.type_)


class EnumStruct(object):

    def __init__(self, entries):
        entries = dict((v.replace(' ', '_').upper(), k) for k, v in entries.iteritems())
        self.__dict__.update(entries)

TLS_VERSIONS = {
    # SSL
    0x0002: "SSL_2_0",
    0x0300: "SSL_3_0",
    # TLS:
    0x0301: "TLS_1_0",
    0x0302: "TLS_1_1",
    0x0303: "TLS_1_2",
    0x0304: "TLS_1_3",
    # DTLS
    0x0100: "PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f",
    0x7f10: "TLS_1_3_DRAFT_16",
    0x7f12: "TLS_1_3_DRAFT_18",
    0xfeff: "DTLS_1_0",
    0xfefd: "DTLS_1_1",
}
TLSVersion = EnumStruct(TLS_VERSIONS)

TLS_CONTENT_TYPES = registry.TLS_CONTENTTYPE_REGISTRY
TLSContentType = EnumStruct(TLS_CONTENT_TYPES)

TLS_HANDSHAKE_TYPES = registry.TLS_HANDSHAKETYPE_REGISTRY
TLS_HANDSHAKE_TYPES.update({0x6: "hello_retry_request",
                            0x8: "encrypted_extensions",
                            0x18: "key_update"})
TLSHandshakeType = EnumStruct(TLS_HANDSHAKE_TYPES)

TLS_EXTENSION_TYPES = registry.EXTENSIONTYPE_VALUES
TLS_EXTENSION_TYPES.update({0x3374: "next_protocol_negotiation",
                            40: "key_share",
                            41: "pre_shared_key",
                            42: "early_data",
                            43: "supported_versions",
                            44: "cookie",
                            45: "psk_key_exchange_modes",
                            46: "ticket_early_data_info"})    # manually add NPN as it is not in iana registry
TLSExtensionType = EnumStruct(TLS_EXTENSION_TYPES)

TLS_ALERT_LEVELS = {
    0x01: "warning",
    0x02: "fatal",
    0xff: "unknown",
}
TLSAlertLevel = EnumStruct(TLS_ALERT_LEVELS)

TLS_ALERT_DESCRIPTIONS = registry.TLS_ALERT_REGISTRY
TLS_ALERT_DESCRIPTIONS.update({1: "end_of_early_data",
                               109: "missing_extension",
                               116: "certificate_required"})
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
    0x0066: 'DHE_DSS_WITH_RC4_128_SHA',
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x1304: 'TLS_AES_128_CCM_SHA256',
    0x1305: 'TLS_AES_128_CCM_8_SHA256'})
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

TLS_EC_POINT_FORMATS = registry.TLS_EC_POINT_FORMAT_REGISTRY
TLSEcPointFormat = EnumStruct(TLS_EC_POINT_FORMATS)
# Fix inconsistency in casing
TLSECPointFormat = TLSEcPointFormat
DEFAULT_EC_POINT_FORMAT_LIST = [TLSECPointFormat.UNCOMPRESSED]

TLS_EC_CURVE_TYPES = registry.TLS_EC_CURVE_TYPE_REGISTRY
TLSECCurveTypes = EnumStruct(TLS_EC_CURVE_TYPES)

TLS_SUPPORTED_GROUPS = registry.TLS_SUPPORTED_GROUPS_REGISTRY
TLS_SUPPORTED_GROUPS.update({256: "ffdhe2048",
                             257: "ffdhe3072",
                             258: "ffdhe4096",
                             259: "ffdhe6144",
                             260: "ffdhe8192"})
TLSSupportedGroup = EnumStruct(TLS_SUPPORTED_GROUPS)
DEFAULT_NAMED_GROUP_LIST = [TLSSupportedGroup.SECP256R1, TLSSupportedGroup.SECP384R1, TLSSupportedGroup.SECP521R1]

TLS_HASH_ALGORITHMS = registry.TLS_HASHALGORITHM_REGISTRY
TLSHashAlgorithm = EnumStruct(TLS_HASH_ALGORITHMS)

TLS_SIGNATURE_ALGORITHMS = registry.TLS_SIGNATUREALGORITHM_REGISTRY
TLSSignatureAlgorithm = EnumStruct(TLS_SIGNATURE_ALGORITHMS)

TLS_CERTIFICATE_TYPE_IDENTIFIERS = registry.TLS_CLIENTCERTIFICATETYPE_IDENTIFIERS_REGISTRY
TLSCertificateTypeIdentifier = EnumStruct(TLS_CERTIFICATE_TYPE_IDENTIFIERS)

# Convert TLS 1.2 sig_hash values to TLS 1.3 sig schemes
TLS_SIGNATURE_SCHEMES = {}
for hash_alg, hash_name in TLS_HASH_ALGORITHMS.items():
    for sig_alg, sig_name in TLS_SIGNATURE_ALGORITHMS.items():
        TLS_SIGNATURE_SCHEMES[hash_alg << 8 | sig_alg] = "%s_%s" % (sig_name, hash_name)
# Add or override with the new TLS 1.3 values
TLS_SIGNATURE_SCHEMES.update({# RSA PKCS1v1.5 algorithms
                              0x0201: "rsa_pkcs1_sha1",
                              0x0401: "rsa_pkcs1_sha256",
                              0x0501: "rsa_pkcs1_sha384",
                              0x0601: "rsa_pkcs1_sha512",
                              # ECDSA algorithms
                              0x0403: "ecdsa_secp256r1_sha256",
                              0x0503: "ecdsa_secp384r1_sha384",
                              0x0603: "ecdsa_secp521r1_sha512",
                              # RSA PSS algorithms
                              0x0804: "rsa_pss_sha256",
                              0x0805: "rsa_pss_sha384",
                              0x0806: "rsa_pss_sha512",
                              # EDDSA algorithms
                              0x0807: "ed25519",
                              0x0808: "ed448"})
TLSSignatureScheme = EnumStruct(TLS_SIGNATURE_SCHEMES)
# Might be worth simply using TLS_SIGNATURE_SCHEMES.keys(), reverse sorted?
DEFAULT_SIG_SCHEME_LIST = [TLSSignatureScheme.ECDSA_SECP521R1_SHA512,
                           TLSSignatureScheme.ECDSA_SECP384R1_SHA384,
                           TLSSignatureScheme.ECDSA_SECP256R1_SHA256,
                           TLSSignatureScheme.RSA_PKCS1_SHA512,
                           TLSSignatureScheme.RSA_PKCS1_SHA384,
                           TLSSignatureScheme.RSA_PKCS1_SHA256,
                           # Leave SHA1 for now, for ease of testing
                           TLSSignatureScheme.RSA_PKCS1_SHA1]


TLS_PSK_KEY_EXCHANGE_MODE = {}
TLS_PSK_KEY_EXCHANGE_MODE.update({0: "psk_ke",
                                  1: "psk_dhe_ke",
                                  255: "reserved"})
TLSPSKKeyExchangeMode = EnumStruct(TLS_PSK_KEY_EXCHANGE_MODE)

TLS_CERTIFICATE_STATUS_TYPES = registry.TLS_CERTIFICATE_STATUS_TYPES
TLSCertificateStatusType = EnumStruct(TLS_CERTIFICATE_STATUS_TYPES)


class TLSKexNames(object):
    RSA = "RSA"
    DHE = "DHE"
    ECDHE = "ECDHE"


class TLSFragmentationError(Exception):
    pass


class TLSRecord(StackedLenPacket):
    MAX_LEN = 2**16 - 1
    name = "TLS Record"
    fields_desc = [ByteEnumField("content_type", TLSContentType.APPLICATION_DATA, TLS_CONTENT_TYPES),
                   XShortEnumField("version", TLSVersion.TLS_1_0, TLS_VERSIONS),
                   XLenField("length", None, fmt="!H")]

    def __init__(self, *args, **fields):
        self.fragments = []
        StackedLenPacket.__init__(self, *args, **fields)

    def guess_payload_class(self, payload):
        """ Sense for ciphertext
        """
        cls = StackedLenPacket.guess_payload_class(self, payload)
        p = cls(payload, _internal=1, _underlayer=self)
        if p.haslayer(TLSHandshakes) and len(p[TLSHandshakes].handshakes) > 0:
            p = p[TLSHandshakes].handshakes[0]
        try:
            if cls == Raw().__class__ or p.length > len(payload):
                # length does not fit len raw_bytes, assume its corrupt or encrypted
                cls = TLSCiphertext
        except AttributeError:
            # e.g. TLSChangeCipherSpec might land here
            pass
        return cls

    def do_build(self):
        """
        Just raises exception when payload can't fit in a TLSRecord
        """
        if len(self.payload) > TLSRecord.MAX_LEN:
            raise TLSFragmentationError()
        return StackedLenPacket.do_build(self)

    def fragment(self, size=2**14):
        return tls_fragment_payload(self.payload, self, size)


class TLSServerName(PacketNoPayload):
    name = "TLS Servername"
    fields_desc = [ByteEnumField("type", 0x00, {0x00: "host"}),
                   XFieldLenField("length", None, length_of="data", fmt="H"),
                   StrLenField("data", "", length_from=lambda x: x.length)]


class TLSExtServerNameIndication(PacketNoPayload):
    name = "TLS Extension Servername Indication"
    fields_desc = [XFieldLenField("length", None, length_of="server_names", fmt="H"),
                   PacketListField("server_names", None, TLSServerName, length_from=lambda x:x.length)]

# https://tools.ietf.org/html/rfc7301


class TLSALPNProtocol(PacketNoPayload):
    name = "TLS ALPN Protocol"
    fields_desc = [XFieldLenField("length", None, length_of="data", fmt="B"),
                   StrLenField("data", "", length_from=lambda x:x.length)]
DEFAULT_ALPN_LIST = [TLSALPNProtocol(data="h2"), TLSALPNProtocol(data="http/1.1")]


class TLSExtALPN(PacketNoPayload):
    name = "TLS Extension Application-Layer Protocol Negotiation"
    fields_desc = [XFieldLenField("length", None, length_of="protocol_name_list", fmt="H"),
                   PacketListField("protocol_name_list", DEFAULT_ALPN_LIST, TLSALPNProtocol, length_from=lambda x:x.length)]


class TLSExtension(PacketLengthFieldPayload):
    name = "TLS Extension"
    fields_desc = [XShortEnumField("type", TLSExtensionType.SERVER_NAME, TLS_EXTENSION_TYPES),
                   XLenField("length", None, fmt="!H")]

    def __init__(self, *args, **fields):
        # This tells us from which context we have been called from. It will hold the name of the calling packet,
        # but could be any metadata
        self.type_ = fields.pop("type_", None)
        PacketLengthFieldPayload.__init__(self, *args, **fields)


class TLSExtMaxFragmentLength(PacketNoPayload):
    name = "TLS Extension Max Fragment Length"
    fields_desc = [ByteEnumField("fragment_length", 0xff, TLS_EXT_MAX_FRAGMENT_LENGTH_ENUM)]


class TLSURLAndOptionalHash(PacketNoPayload):
    name = "TLS Extension Certificate URL/Hash"
    fields_desc = [XFieldLenField("url_length", None, length_of="url", fmt="H"),
                   StrLenField("url", "", length_from=lambda x:x.url_length),
                   ByteEnumField("hash_present", TLSTypeBoolean.FALSE, TLS_TYPE_BOOLEAN),
                   StrLenField("sha1hash", "", length_from=lambda x:20 if x.hash_present else 0)]


class TLSExtCertificateURL(PacketNoPayload):
    name = "TLS Extension Certificate URL"
    fields_desc = [ByteEnumField("type", TLSCertChainType.INDIVIDUAL_CERTS, TLS_CERT_CHAIN_TYPE),
                   XFieldLenField("length", None, length_of="certificate_urls", fmt="H"),
                   PacketListField("certificate_urls", None, TLSURLAndOptionalHash, length_from=lambda x:x.length)]


class TLSExtECPointsFormat(PacketNoPayload):
    name = "TLS Extension EC Points Format"
    fields_desc = [XFieldLenField("length", None, length_of="ec_point_formats", fmt="B"),
                   ReprFieldListField("ec_point_formats", DEFAULT_EC_POINT_FORMAT_LIST,
                                      ByteEnumField("ec_point_format", None, TLS_EC_POINT_FORMATS),
                                      length_from=lambda x:x.length)]


class TLSExtSupportedGroups(PacketNoPayload):
    name = "TLS Extension Supported Groups"
    fields_desc = [XFieldLenField("length", None, length_of="named_group_list", fmt="H"),
                   ReprFieldListField("named_group_list", DEFAULT_NAMED_GROUP_LIST,
                                      ShortEnumField("named_group", None, TLS_SUPPORTED_GROUPS),
                                      length_from=lambda x:x.length)]
TLSExtEllipticCurves = TLSExtSupportedGroups


class TLSExtSignatureAlgorithms(PacketNoPayload):
    name = "TLS Extension Signature Algorithms"
    fields_desc = [XFieldLenField("length", None, length_of="algs", fmt="H"),
                   ReprFieldListField("algs", DEFAULT_SIG_SCHEME_LIST, ShortEnumField("length", None, TLS_SIGNATURE_SCHEMES),
                                      length_from=lambda x: x.length)]


class TLSExtHeartbeat(PacketNoPayload):
    name = "TLS Extension HeartBeat"
    fields_desc = [ByteEnumField("mode", TLSHeartbeatMode.PEER_NOT_ALLOWED_TO_SEND, TLS_HEARTBEAT_MODE)]


class TLSExtSessionTicketTLS(PacketNoPayload):
    name = "TLS Extension SessionTicket TLS"
    fields_desc = [StrLenField("data", '', length_from=lambda x:x.underlayer.length)]


class TLSExtRenegotiationInfo(PacketNoPayload):
    name = "TLS Extension Renegotiation Info"
    fields_desc = [XFieldLenField("length", None, length_of="data", fmt="B"),
                   StrLenField("data", '', length_from=lambda x:x.length)]


class TLSOCSPResponderID(PacketNoPayload):
    name = "TLS OCSP Responder ID"
    fields_desc = [XFieldLenField("length", None, length_of="responder_id", fmt="H"),
                   StrLenField("responder_id", "", length_from=lambda x: x.length)]


class TLSExtCertificateStatusRequest(PacketNoPayload):
    name = "TLS Extension Certificate Status Request"
    fields_desc = [ByteEnumField("status_type", TLSCertificateStatusType.OCSP, TLS_CERTIFICATE_STATUS_TYPES),
                   XFieldLenField("responder_id_length", None, length_of="responder_id_list", fmt="H"),
                   PacketListField("responder_id_list", None, TLSOCSPResponderID, length_from=lambda x: x.responder_id_length),
                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                   StrLenField("extensions", "", length_from=lambda x: x.extensions_length)]


# TLS 1.3 specific extensions
class TLSExtSupportedVersions(PacketNoPayload):
    name = "TLS Extension Supported Versions"
    fields_desc = [XFieldLenField("length", None, length_of="versions", fmt="B"),
                   ReprFieldListField("versions", [TLSVersion.TLS_1_3], XShortEnumField("version", None, TLS_VERSIONS),
                                      length_from=lambda x: x.length)]


class TLSExtCookie(PacketNoPayload):
    name = "TLS Extension Cookie"
    fields_desc = [XFieldLenField("length", None, length_of="cookie", fmt="H"),
                   StrLenField("cookie", "", length_from=lambda x: x.length)]


class TLSKeyShareEntry(PacketNoPayload):
    name = "TLS Key Share Entry"
    fields_desc = [ShortEnumField("named_group", None, TLS_SUPPORTED_GROUPS),
                   XFieldLenField("length", None, length_of="key_exchange", fmt="H"),
                   StrLenField("key_exchange", "", length_from=lambda x: x.length)]


class TLSClientHelloKeyShare(PacketNoPayload):
    name = "TLS Client Hello Key Share"
    fields_desc = [XFieldLenField("length", None, length_of="client_shares", fmt="H"),
                   PacketListField("client_shares", None, TLSKeyShareEntry, length_from=lambda x:x.length)]


class TLSHelloRetryRequestKeyShare(PacketNoPayload):
    name = "TLS Hello Retry Request Key Share"
    fields_desc = [ShortEnumField("selected_group", None, TLS_SUPPORTED_GROUPS)]


class TLSServerHelloKeyShare(PacketNoPayload):
    name = "TLS Server Hello Key Share"
    fields_desc = [PacketField("server_share", None, TLSKeyShareEntry)]


class TLSExtKeyShare(Packet):
    name = "TLS Extension Key Share"
    fields_desc = []
    type_map = {"TLSHelloRetryRequest": TLSHelloRetryRequestKeyShare,
                "TLSClientHello": TLSClientHelloKeyShare,
                "TLSServerHello": TLSServerHelloKeyShare}

    def guess_payload_class(self, raw_bytes):
        pkt = self.underlayer
        # If our underlayer is an extension whose type_ is defined
        # Use this as the upper layer
        if pkt is not None and pkt.haslayer(TLSExtension):
            upper_cls = TLSExtKeyShare.type_map.get(pkt.type_)
            if upper_cls is not None:
                return upper_cls
        # Otherwise, revert to default payload guessing
        return Packet.guess_payload_class(self, raw_bytes)


class TLSPSKIdentity(PacketNoPayload):
    name = "TLS PSK Identity"
    fields_desc = [XFieldLenField("length", None, length_of="identity", fmt="H"),
                   StrLenField("identity", "", length_from=lambda x: x.length),
                   XIntField("obfuscated_ticket_age", 0)]


class TLSPSKBinderEntry(PacketNoPayload):
    name = "TLS PSK Binder Entry"
    fields_desc = [XFieldLenField("length", None, length_of="binder_entry", fmt="B"),
                   StrLenField("binder_entry", "", length_from=lambda x: x.length)]


class TLSClientHelloPreSharedKey(PacketNoPayload):
    name = "TLS Client Hello Pre Shared Key"
    fields_desc = [XFieldLenField("identities_length", None, length_of="identities", fmt="H"),
                   PacketListField("identities", None, TLSPSKIdentity, length_from=lambda x:x.identities_length),
                   XFieldLenField("binders_length", None, length_of="binders", fmt="H"),
                   PacketListField("binders", None, TLSPSKBinderEntry, length_from=lambda x: x.binders_length)]


class TLSServerHelloPreSharedKey(PacketNoPayload):
    name = "TLS Server Hello Pre Shared Key"
    fields_desc = [XShortField("selected_identity", 0)]


class TLSExtPreSharedKey(Packet):
    name = "TLS Extension Pre Shared Key"
    fields_desc = []
    type_map = {"TLSClientHello": TLSClientHelloPreSharedKey,
                "TLSServerHello": TLSServerHelloPreSharedKey}

    def guess_payload_class(self, raw_bytes):
        pkt = self.underlayer
        # If our underlayer is an extension whose type_ is defined
        # Use this as the upper layer
        if pkt is not None and pkt.haslayer(TLSExtension):
            upper_cls = TLSExtPreSharedKey.type_map.get(pkt.type_)
            if upper_cls is not None:
                return upper_cls
        # Otherwise, revert to default payload guessing
        return Packet.guess_payload_class(self, raw_bytes)


class TLSExtPadding(PacketNoPayload):
    name = "TLS Extension Padding"
    fields_desc = [StrField("padding", b"\x00" * 16)]


class TLSExtPSKKeyExchangeModes(PacketNoPayload):
    name = "TLS Extension PSK Key Exchange Mode"
    fields_desc = [XFieldLenField("length", None, length_of="ke_modes", fmt="B"),
                   ReprFieldListField("ke_modes", [TLSPSKKeyExchangeMode.PSK_DHE_KE], ByteEnumField("ke_mode", None, TLS_PSK_KEY_EXCHANGE_MODE),
                                      length_from=lambda x: x.length)]


class TLSHelloRequest(Packet):
    name = "TLS Hello Request"
    fields_desc = []


class TLSHelloRetryRequest(Packet):
    name = "TLS Hello Retry Request"
    fields_desc = [XShortEnumField("version", TLSVersion.TLS_1_3, TLS_VERSIONS),
                   XFieldLenField("length", None, length_of="extensions", fmt="H"),
                   TypedPacketListField("extensions", None, TLSExtension, length_from=lambda x:x.length, type_="TLSHelloRetryRequest")]


class TLSEncryptedExtensions(PacketNoPayload):
    name = "TLS Encrypted Extensions"
    fields_desc = [XFieldLenField("length", None, length_of="extensions", fmt="H"),
                   TypedPacketListField("extensions", None, TLSExtension, length_from=lambda x:x.length, type_="TLSEncryptedExtensions")]


class TLSClientHello(PacketNoPayload):
    name = "TLS Client Hello"
    fields_desc = [XShortEnumField("version", TLSVersion.TLS_1_2, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   ReprFieldListField("cipher_suites", [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA], XShortEnumField("cipher", None, TLS_CIPHER_SUITES),
                                      length_from=lambda x: x.cipher_suites_length),
                   XFieldLenField("compression_methods_length", None, length_of="compression_methods", fmt="B"),
                   ReprFieldListField("compression_methods", [TLSCompressionMethod.NULL],
                                      ByteEnumField("compression", None, TLS_COMPRESSION_METHODS),
                                      length_from=lambda x:x.compression_methods_length),
                   StrConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                                       lambda pkt, s, val: True if val or pkt.extensions or (s and struct.unpack("!H", s[:2])[0] == len(s) - 2) else False),
                   TypedPacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length, type_="TLSClientHello")]


class TLSServerHello(PacketNoPayload):
    name = "TLS Server Hello"
    fields_desc = [XShortEnumField("version", TLSVersion.TLS_1_2, TLS_VERSIONS),
                   # TLS 1.2: TLS 1.3 random does not start by a timestamp
                   ConditionalField(IntField("gmt_unix_time", int(time.time())), lambda pkt: pkt.version < TLSVersion.TLS_1_3),
                   ConditionalField(StrFixedLenField("random_bytes", os.urandom(28), 28), lambda pkt: pkt.version < TLSVersion.TLS_1_3),
                   # TLS 1.3 random is 32 random bytes only
                   ConditionalField(StrFixedLenField("random", os.urandom(32), 32), lambda pkt: pkt.version >= TLSVersion.TLS_1_3),
                   # Fields are not in TLS 1.3, moved to a proper psk extension
                   ConditionalField(XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"), lambda pkt: pkt.version < TLSVersion.TLS_1_3),
                   ConditionalField(StrLenField("session_id", os.urandom(20), length_from=lambda x:x.session_id_length),
                                    lambda pkt: pkt.version < TLSVersion.TLS_1_3),
                   XShortEnumField("cipher_suite", TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA, TLS_CIPHER_SUITES),
                   # Field deprecated in TLS 1.3
                   ConditionalField(ByteEnumField("compression_method", TLSCompressionMethod.NULL, TLS_COMPRESSION_METHODS),
                                    lambda pkt: pkt.version < TLSVersion.TLS_1_3),
                   StrConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                                       lambda pkt, s, val: True if val or pkt.extensions or (s and struct.unpack("!H", s[:2])[0] == len(s) - 2) else False),
                   TypedPacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length, type_="TLSServerHello")]


class TLSSessionTicket(PacketNoPayload):
    name = "TLS Session Ticket"
    fields_desc = [IntField("lifetime", 7200),
                   XFieldLenField("ticket_length", None, length_of="ticket", fmt="!H"),
                   StrLenField("ticket", '', length_from=lambda x:x.ticket_length)]


class TLSHeartBeat(PacketNoPayload):
    name = "TLS HeartBeat"
    fields_desc = [ByteEnumField("type", TLSHeartbeatMessageType.HEARTBEAT_REQUEST, TLS_HEARTBEAT_MESSAGE_TYPE),
                   FieldLenField("length", None, length_of="data", fmt="H"),
                   StrLenField("data", "", length_from=lambda x:x.length),
                   StrLenField("padding", "", length_from=lambda x: 'P' * (16 - x.length))]


class TLSKeyExchange(Packet):
    def __init__(self, *args, **fields):
        # Unneeded, left for backwards compat
        self.tls_ctx = fields.pop("ctx", None)
        Packet.__init__(self, *args, **fields)

    def guess_payload_class(self, payload):
        pkt = self.underlayer
        # If our underlayer is a handshake, use the tls_ctx to determine
        # wheat KEX we are currently using
        if pkt is not None and pkt.haslayer(TLSHandshake) and hasattr(pkt, "tls_ctx"):
            if pkt.tls_ctx is not None:
                kex = pkt.tls_ctx.negotiated.key_exchange
                return self.kex_payload_table.get(kex, Raw)
        return Packet.guess_payload_class(self, payload)


class TLSClientRSAParams(PacketNoPayload):
    name = "TLS RSA Client Params"
    # Length field needs to be removed for SSL3 compatibility. I don't care for now
    fields_desc = [XFieldLenField("length", None, length_of="data", fmt="!H"),
                   StrLenField("data", "", length_from=lambda x:x.length)]


class TLSClientDHParams(PacketNoPayload):
    name = "TLS Diffie-Hellman Client Params"
    # Length field needs to be removed for SSL3 compatibility. I don't care for now
    fields_desc = [XFieldLenField("length", None, length_of="data", fmt="!H"),
                   StrLenField("data", "", length_from=lambda x:x.length)]


class TLSClientECDHParams(PacketNoPayload):
    name = "TLS EC Diffie-Hellman Client Params"
    # Another brilliant TLS idea. Let's hold ECDHE param length on 1 byte instead of 2
    fields_desc = [XFieldLenField("length", None, length_of="data", fmt="!B"),
                   StrLenField("data", "", length_from=lambda x:x.length)]


class TLSClientKeyExchange(TLSKeyExchange):
    name = "TLS Client Key Exchange"
    kex_payload_table = {TLSKexNames.RSA: TLSClientRSAParams,
                         TLSKexNames.DHE: TLSClientDHParams,
                         TLSKexNames.ECDHE: TLSClientECDHParams}

    def guess_payload_class(self, payload):
        ecdh_params = TLSClientECDHParams(payload)
        # Try to figure out what is the next Key Exchange layer. Can only do this for ECDHE,
        # since RSA and DHE parse in exactly the same way.
        if ecdh_params.length == len(ecdh_params.data) and ecdh_params.data.startswith(b"\x04"):
            return TLSClientECDHParams
        else:
            return TLSKeyExchange.guess_payload_class(self, payload)


class TLSServerDHParams(PacketNoPayload):
    name = "TLS Diffie-Hellman Server Params"
    fields_desc = [XFieldLenField("p_length", None, length_of="p", fmt="!H"),
                   StrLenField("p", '', length_from=lambda x:x.p_length),
                   XFieldLenField("g_length", None, length_of="g", fmt="!H"),
                   StrLenField("g", '', length_from=lambda x:x.g_length),
                   XFieldLenField("ys_length", None, length_of="y_s", fmt="!H"),
                   StrLenField("y_s", "", length_from=lambda x:x.ys_length),
                   ShortEnumField("scheme_type", TLSSignatureScheme.RSA_PKCS1_SHA256, TLS_SIGNATURE_SCHEMES),
                   XFieldLenField("sig_length", None, length_of="sig", fmt="!H"),
                   StrLenField("sig", '', length_from=lambda x:x.sig_length)]


class TLSServerECDHParams(PacketNoPayload):
    name = "TLS EC Diffie-Hellman Server Params"
    fields_desc = [ByteEnumField("curve_type", TLSECCurveTypes.NAMED_CURVE, TLS_EC_CURVE_TYPES),
                   ShortEnumField("curve_name", TLSSupportedGroup.SECP256R1, TLS_SUPPORTED_GROUPS),
                   XFieldLenField("p_length", None, length_of="p", fmt="!B"),
                   StrLenField("p", '', length_from=lambda x:x.p_length),
                   ShortEnumField("scheme_type", TLSSignatureScheme.RSA_PKCS1_SHA256, TLS_SIGNATURE_SCHEMES),
                   XFieldLenField("sig_length", None, length_of="sig", fmt="!H"),
                   StrLenField("sig", '', length_from=lambda x:x.sig_length)]


class TLSServerKeyExchange(TLSKeyExchange):
    name = "TLS Server Key Exchange"
    kex_payload_table = {TLSKexNames.DHE: TLSServerDHParams,
                         TLSKexNames.ECDHE: TLSServerECDHParams}

    def guess_payload_class(self, payload):
        dh_params = TLSServerDHParams(payload)
        ecdh_params = TLSServerECDHParams(payload)
        # Try to figure out what is the next Key Exchange layer
        if dh_params.p_length == len(dh_params.p) and dh_params.g_length == len(dh_params.g) and \
                        dh_params.ys_length == len(dh_params.y_s) and dh_params.sig_length == len(dh_params.sig):
            return TLSServerDHParams
        elif ecdh_params.p_length == len(ecdh_params.p) and ecdh_params.sig_length == len(ecdh_params.sig):
            return TLSServerECDHParams
        # If we don't have a match, fallback to the standard mechanism
        else:
            return TLSKeyExchange.guess_payload_class(payload)


class TLSServerHelloDone(PacketNoPayload):
    name = "TLS Server Hello Done"
    fields_desc = []


class TLSCertificate(PacketNoPayload):
    name = "TLS Certificate"
    fields_desc = [XBLenField("length", None, length_of="data", fmt="!I", numbytes=3),
                   PacketLenField("data", None, x509.X509Cert, length_from=lambda x:x.length)]


class TLS10Certificate(PacketNoPayload):
    name = "TLS 1.0 Certificates"
    fields_desc = [XBLenField("length", None, length_of="certificates", fmt="!I", numbytes=3),
                   PacketListField("certificates", None, TLSCertificate, length_from=lambda x: x.length)]


class TLSCertificateEntry(PacketNoPayload):
    name = "TLS Certificate Entry"
    fields_desc = [XBLenField("length", None, length_of="cert_data", fmt="!I", numbytes=3),
                   PacketLenField("cert_data", None, x509.X509Cert, length_from=lambda x: x.length),
                   XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x: x.extensions_length)]


class TLS13Certificate(PacketNoPayload):
    name = "TLS 1.3 Certificates"
    fields_desc = [XFieldLenField("request_context_length", None, length_of="request_context", fmt="B"),
                   StrLenField("request_context", "", length_from=lambda x: x.request_context_length),
                   XBLenField("length", None, length_of="certificates", fmt="!I", numbytes=3),
                   PacketListField("certificates", None, TLSCertificateEntry, length_from=lambda x: x.length)]


class TLSCertificateList(Packet):
    name = "TLS Certificate List"
    fields_desc = []

    def guess_payload_class(self, payload):
        tls13_cert = TLS13Certificate(payload)
        tls10_cert = TLS10Certificate(payload)
        certs_len = lambda certs: len(b"".join([str(cert) for cert in certs.certificates]))
        if tls13_cert.request_context_length == len(tls13_cert.request_context) and tls13_cert.length == certs_len(tls13_cert):
            return TLS13Certificate
        elif tls10_cert.length == certs_len(tls10_cert):
            return TLS10Certificate
        else:
            pkt = self.underlayer
            # If our underlayer is a handshake, use the tls_ctx to determine
            # whether we are using a tls 1.3 cert or an older version
            if pkt is not None and pkt.haslayer(TLSHandshake):
                if pkt.tls_ctx is not None:
                    if pkt.tls_ctx.negotiated.version >= TLSVersion.TLS_1_3:
                        return TLS13Certificate
            return TLS10Certificate


class TLSCertificateVerify(PacketNoPayload):
    name = "TLS Certificate Verify"
    fields_desc = [ShortEnumField("alg", TLSSignatureScheme.RSA_PKCS1_SHA256, TLS_SIGNATURE_SCHEMES),
                   XFieldLenField("sig_length", None, length_of="sig", fmt="H"),  # ASN.1 signature element
                   StrLenField("sig", "", length_from=lambda x:x.sig_length)]


class TLSCertificateType(PacketNoPayload):
    name = "TLS Certificate Type"
    fields_desc = [ByteEnumField("type", TLSCertificateTypeIdentifier.RSA_SIGN, TLS_CERTIFICATE_TYPE_IDENTIFIERS)]


class TLSCADistinguishedName(PacketNoPayload):
    name = "TLS CA Distinguished Name"
    fields_desc = [XFieldLenField("length", None, length_of="dn", fmt="H"),
                   PacketLenField("ca_dn", None, x509.X509v3Ext, length_from=lambda x:x.length)]


class TLSCertificateRequest(Packet):
    name = "TLS Certificate Request"
    fields_desc = [XFieldLenField("type_length", None, length_of="types", fmt="B"),
                   PacketListField("types", TLSCertificateType(), TLSCertificateType, length_from=lambda x: x.type_length),
                   XFieldLenField("alg_length", None, length_of="algs", fmt="H"),
                   ReprFieldListField("algs", DEFAULT_SIG_SCHEME_LIST, ShortEnumField("alg", None, TLS_SIGNATURE_SCHEMES),
                                      length_from=lambda x: x.alg_length),
                   XFieldLenField("dn_length", None, length_of="ca_dns", fmt="H"),
                   PacketListField("ca_dns", None, TLSCADistinguishedName, length_from=lambda x: x.dn_length)]


class TLSDecryptablePacket(PacketLengthFieldPayload):

    explicit_iv_field = StrField("explicit_iv", "", fmt="H")
    mac_field = StrField("mac", "", fmt="H")
    padding_field = StrLenField("padding", "", length_from=lambda pkt: pkt.padding_len)
    padding_len_field = ConditionalField(
        XFieldLenField("padding_len", None, length_of="padding", fmt="B"),
        lambda pkt: True if pkt and hasattr(pkt, "padding") and pkt.padding != "" else False)
    decryptable_fields = [mac_field, padding_field, padding_len_field]

    def __init__(self, *args, **fields):
        try:
            self.tls_ctx = fields["ctx"]
            del(fields["ctx"])
            if self.explicit_iv_field not in self.fields_desc and self.tls_ctx.requires_iv:
                self.fields_desc.append(self.explicit_iv_field)
            for field in self.decryptable_fields:
                if field not in self.fields_desc:
                    self.fields_desc.append(field)
        except KeyError:
            self.tls_ctx = None
        PacketLengthFieldPayload.__init__(self, *args, **fields)

    def pre_dissect(self, raw_bytes):
        data = raw_bytes
        if self.tls_ctx is not None:
            import ssl_tls_crypto as tlsc
            hash_size = self.tls_ctx.sec_params.mac_key_length
            iv_size = self.tls_ctx.sec_params.iv_length
            # CBC mode
            if self.tls_ctx.sec_params.cipher_mode_name == tlsc.CipherMode.CBC:
                try:
                    self.padding_len = ord(raw_bytes[-1])
                    self.padding = raw_bytes[-self.padding_len - 1:-1]
                    self.mac = raw_bytes[-self.padding_len - hash_size - 1:-self.padding_len - 1]
                    if self.tls_ctx.requires_iv:
                        self.explicit_iv = raw_bytes[:iv_size]
                        data = raw_bytes[iv_size:-self.padding_len - hash_size - 1]
                    else:
                        data = raw_bytes[:-self.padding_len - hash_size - 1]
                except IndexError:
                    data = raw_bytes
            elif self.tls_ctx.sec_params.cipher_mode_name == tlsc.CipherMode.EAEAD:
                self.explicit_iv = raw_bytes[:self.tls_ctx.sec_params.GCM_EXPLICIT_IV_SIZE]
                self.mac = raw_bytes[-self.tls_ctx.sec_params.GCM_TAG_SIZE:]
                data = raw_bytes[self.tls_ctx.sec_params.GCM_EXPLICIT_IV_SIZE:-self.tls_ctx.sec_params.GCM_TAG_SIZE]
            elif self.tls_ctx.sec_params.cipher_mode_name == tlsc.CipherMode.IAEAD:
                self.mac = raw_bytes[-self.tls_ctx.sec_params.GCM_TAG_SIZE:]
                cleartext = raw_bytes[:-self.tls_ctx.sec_params.GCM_TAG_SIZE]
                padding_index = find_padding_start(cleartext)
                self.padding = cleartext[padding_index:]
                self.padding_len = len(self.padding)
                data = cleartext[:padding_index - 1]
            else:
                self.mac = raw_bytes[-hash_size:]
                data = raw_bytes[:-hash_size]
        # Try and obtain the context from the underlying Record context
        else:
            if self.tls_ctx is None and self.underlayer is not None and isinstance(self.underlayer, TLSRecord):
                if self.underlayer.tls_ctx is not None:
                    self.tls_ctx = self.underlayer.tls_ctx
        # Return plaintext without mac and padding
        return data

    def do_dissect(self, raw_bytes):
        # Required to walk around scapy 2.3.1 bug
        self.raw_packet_cache_fields = {}
        # Taken from Packet.do_dissect
        fields = self.fields_desc[:]
        # Remove the crypto fields. Should not be used for dissection
        for field in self.decryptable_fields + [self.explicit_iv_field]:
            if field in fields:
                fields.remove(field)
        # Identical to Packet.do_dissect()
        fields.reverse()
        raw = raw_bytes
        while raw_bytes and fields:
            field = fields.pop()
            raw_bytes, field_value = field.getfield(self, raw_bytes)
            if field.islist or field.holds_packets:
                self.raw_packet_cache_fields[field.name] = field.do_copy(field_value)
            self.fields[field.name] = field_value
        assert(raw.endswith(raw_bytes))
        if raw_bytes:
            self.raw_packet_cache = raw[:-len(raw_bytes)]
        else:
            self.raw_packet_cache = raw
        self.explicit = 1
        return raw_bytes

    def getfieldval(self, attr):
        if attr in self.fields:
            return self.fields[attr]
        if attr in self.overloaded_fields:
            return self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.default_fields[attr]
        # Ugly hack, to prevent passing crypto fields to upper layers
        # Not sure how to do otherwise though
        if attr in ("explicit_iv", "mac", "padding", "padding_len"):
            return ""
        return self.payload.getfieldval(attr)


class TLSHandshake(PacketLengthFieldPayload):
    name = "TLS Handshake"
    fields_desc = [ByteEnumField("type", TLSHandshakeType.CLIENT_HELLO, TLS_HANDSHAKE_TYPES),
                   XBLenField("length", None, fmt="!I", numbytes=3)]

    def __init__(self, *args, **fields):
        self.tls_ctx = fields.pop("ctx", None)
        PacketLengthFieldPayload.__init__(self, *args, **fields)


class PacketListFieldContext(PacketListField):
    def m2i(self, pkt, m):
        if pkt is not None and hasattr(pkt, "tls_ctx"):
            return self.cls(m, ctx=pkt.tls_ctx)
        else:
            return PacketListField.m2i(self, pkt, m)


class TLSHandshakes(TLSDecryptablePacket):
    name = "TLS Handshakes"
    fields_desc = [PacketListFieldContext("handshakes", None, TLSHandshake)]


class TLSFinished(PacketNoPayload):
    name = "TLS Handshake Finished"
    fields_desc = [StrLenField("data", "", length_from=lambda x:x.underlayer.length)]


class TLSPlaintext(TLSDecryptablePacket):
    name = "TLS Plaintext"
    fields_desc = [StrField("data", "", fmt="H")]


class TLSChangeCipherSpec(TLSDecryptablePacket):
    name = "TLS ChangeCipherSpec"
    fields_desc = [StrField("message", '\x01', fmt="H")]


class TLSAlert(TLSDecryptablePacket):
    name = "TLS Alert"
    fields_desc = [ByteEnumField("level", TLSAlertLevel.WARNING, TLS_ALERT_LEVELS),
                   ByteEnumField("description", TLSAlertDescription.CLOSE_NOTIFY, TLS_ALERT_DESCRIPTIONS)]


class TLSCiphertext(Packet):
    name = "TLS Ciphertext"
    fields_desc = [StrField("data", None, fmt="H")]


class DTLSRecord(PacketLengthFieldPayload):
    name = "DTLS Record"
    fields_desc = [ByteEnumField("content_type", TLSContentType.APPLICATION_DATA, TLS_CONTENT_TYPES),
                   XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
                   ShortField("epoch", None),
                   XBLenField("sequence", None, fmt="!Q", numbytes=6),
                   XLenField("length", None, fmt="!H")]


class DTLSHandshake(PacketLengthFieldPayload):
    name = "DTLS Handshake"
    fields_desc = TLSHandshake.fields_desc + [ShortField("sequence", None),
                                              XBLenField("fragment_offset", None, fmt="!I", numbytes=3),
                                              XBLenField("length", None, fmt="!I", numbytes=3)]


class DTLSClientHello(PacketNoPayload):
    name = "DTLS Client Hello"
    fields_desc = [XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
                   IntField("gmt_unix_time", int(time.time())),
                   StrFixedLenField("random_bytes", os.urandom(28), 28),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
                   XFieldLenField("cookie_length", None, length_of="cookie", fmt="B"),
                   StrLenField("cookie", '', length_from=lambda x:x.cookie_length),
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   ReprFieldListField("cipher_suites", None, XShortEnumField("cipher", None, TLS_CIPHER_SUITES),
                                      length_from=lambda x:x.cipher_suites_length),
                   XFieldLenField("compression_methods_length", None, length_of="compression_methods", fmt="B"),
                   ReprFieldListField("compression_methods", None,
                                      ByteEnumField("compression", None, TLS_COMPRESSION_METHODS),
                                      length_from=lambda x:x.compression_methods_length),
                   StrConditionalField(XFieldLenField("extensions_length", None, length_of="extensions", fmt="H"),
                                       lambda pkt, s, val: True if val or
                                                                   pkt.extensions or
                                                                   (s and struct.unpack("!H", s[:2])[0] == len(s) - 2)
                                       else False),
                   PacketListField("extensions", None, TLSExtension, length_from=lambda x:x.extensions_length)]

SSLv2_CERTIFICATE_TYPES = {0x01: 'x509'}
SSLv2CertificateType = EnumStruct(SSLv2_CERTIFICATE_TYPES)


class DTLSHelloVerify(PacketNoPayload):
    name = "DTLS Hello Verify"
    fields_desc = [XShortEnumField("version", TLSVersion.DTLS_1_0, TLS_VERSIONS),
                   XFieldLenField("cookie_length", None, length_of="cookie", fmt="B"),
                   StrLenField("cookie", '', length_from=lambda x:x.cookie_length)]


SSLv2_MESSAGE_TYPES = {
    0x01: 'client_hello',
    0x04: 'server_hello',
    0x02: 'client_master_key',
}
SSLv2MessageType = EnumStruct(SSLv2_MESSAGE_TYPES)

SSLv2_CIPHER_SUITES = {
    0x010080: 'RC4_128_WITH_MD5',
    0x020080: 'RC4_128_EXPORT40_WITH_MD5',
    0x040080: 'RC2_CBC_128_CBC_WITH_MD5',
    0x050080: 'IDEA_128_CBC_WITH_MD5',
    0x060040: 'DES_64_CBC_WITH_MD5',
    0x0700c0: 'DES_192_EDE3_CBC_WITH_MD5',
    0x080080: 'RC4_64_WITH_MD5',
    0x030080: 'RC2_CBC_128_CBC_WITH_MD5',
    }

SSLv2CipherSuite = EnumStruct(SSLv2_CIPHER_SUITES)


class SSLv2Record(Packet):
    name = "SSLv2 Record"
    fields_desc = [XBLenField("length", None, fmt="!H", adjust_i2m=lambda pkt, x: x|0x8000, adjust_m2i=lambda pkt, x:x&0x7fff),  # hint SSLv2Record with MSB=1, all other bits=length
                   ByteEnumField("content_type", 0xff, SSLv2_MESSAGE_TYPES),
                   ]

class SSLv2ClientHello(Packet):
    name = "SSLv2 Client Hello"
    fields_desc = [XShortEnumField("version", TLSVersion.SSL_2_0, TLS_VERSIONS),
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   XFieldLenField("session_id_length", None, length_of="session_id", fmt="H"),
                   XFieldLenField("challenge_length", None, length_of="challenge", fmt="H"),
                   ReprFieldListField("cipher_suites", None,
                                      XBEnumField("cipher", None, SSLv2_CIPHER_SUITES, fmt="!I", numbytes=3),
                                      length_from=lambda x:x.cipher_suites_length),
                   StrLenField("session_id", '', length_from=lambda x:x.session_id_length),
                   StrLenField("challenge", '', length_from=lambda x:x.challenge_length)]


class SSLv2ServerHello(Packet):
    name = "SSLv2 Server Hello"
    fields_desc = [ByteEnumField("session_id_hit", TLSTypeBoolean.FALSE, TLS_TYPE_BOOLEAN),
                   ByteEnumField("certificate_type", SSLv2CertificateType.X509, SSLv2_CERTIFICATE_TYPES),
                   XShortEnumField("version", TLSVersion.SSL_2_0, TLS_VERSIONS),
                   XFieldLenField("certificates_length", None, length_of="certificates", fmt="H"),
                   XFieldLenField("cipher_suites_length", None, length_of="cipher_suites", fmt="H"),
                   XFieldLenField("connection_id_length", None, length_of="connection_id", fmt="H"),
                   StrLenField("certificates", '', length_from=lambda x:x.certificates_length),
                   ReprFieldListField("cipher_suites", None,
                                      XBEnumField("cipher", None, SSLv2_CIPHER_SUITES, fmt="!I", numbytes=3),
                                      length_from=lambda x:x.cipher_suites_length),
                   StrLenField("connection_id", '', length_from=lambda x:x.connection_id_length)]


class SSLv2ClientMasterKey(Packet):
    name = "SSLv2 Client Master Key"
    fields_desc = [XBEnumField("cipher_suite", SSLv2CipherSuite.RC4_128_WITH_MD5, SSLv2_CIPHER_SUITES, fmt="!I",
                               numbytes=3),
                   # fixme: 3byte wide
                   XFieldLenField("clear_key_length", None, length_of="clear_key", fmt="H"),
                   XFieldLenField("encrypted_key_length", None, length_of="encrypted_key", fmt="H"),
                   XFieldLenField("key_argument_length", None, length_of="key_argument", fmt="H"),
                   StrLenField("clear_key", '', length_from=lambda x:x.clear_key_length),
                   StrLenField("encrypted_key", '', length_from=lambda x:x.clear_key_length),
                   StrLenField("key_argument", '', length_from=lambda x:x.key_argument_length)]


class TLSSocket(object):

    def __init__(self, sock=socket.socket(), client=None, tls_ctx=None):
        if sock is not None:
            self._s = sock
        else:
            raise ValueError("Socket cannot be None")

        if client is None:
            self.client = self._is_listening()
        else:
            self.client = client

        if tls_ctx is None:
            import ssl_tls_crypto as tlsc
            self.tls_ctx = tlsc.TLSSessionCtx(self.client)
        else:
            self.tls_ctx = tls_ctx
        self.ctx = self.tls_ctx.client_ctx if self.client else self.tls_ctx.server_ctx
        self.compress_hook = None
        self.pre_encrypt_hook = None
        self.encrypt_hook = None

    def _is_listening(self):
        import errno
        import socket
        try:
            is_listening = self._s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except socket.error as se:
            # OSX and BSDs do not support ENOPROTOOPT. Linux and Windows seem to
            if se.errno == errno.ENOPROTOOPT:
                raise RuntimeError("OS does not support SO_ACCEPTCONN, cannot determine socket state. Please supply an"
                                   "explicit client value (True for client, False for server)")
            else:
                raise
        return True if is_listening != 0 else False

    def __getattr__(self, attr):
        try:
            super(TLSSocket, self).__getattr__()
        except AttributeError:
            return getattr(self._s, attr)

    def _get_pkt_origin(self, direction=None):
        if direction=='in':
            return 'server' if self.client else 'client'
        elif direction=='out':
            return 'client' if self.client else 'server'

    def sendall(self, pkt, timeout=2):
        prev_timeout = self._s.gettimeout()
        self._s.settimeout(timeout)
        if self.ctx.must_encrypt:
            self._s.sendall(str(tls_to_raw(pkt, self.tls_ctx, True, self.compress_hook, self.pre_encrypt_hook, self.encrypt_hook)))
        else:
            self._s.sendall(str(pkt))
        self.tls_ctx.insert(pkt, self._get_pkt_origin('out'))
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
        records = TLS("".join(resp), ctx=self.tls_ctx, _origin=self._get_pkt_origin('in'))
        return records

    def accept(self):
        client_socket, peer = self._s.accept()
        return TLSSocket(client_socket, client=False, tls_ctx=copy.copy(self.tls_ctx)), peer

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def do_handshake(self, version, ciphers, extensions=[]):
        return tls_do_handshake(self, version, ciphers, extensions)

    def do_round_trip(self, pkt, recv=True):
        return tls_do_round_trip(self, pkt, recv)


# entry class
class SSL(Packet):
    """
    COMPOUND CLASS for SSL
    """
    name = "SSL/TLS"
    fields_desc = [PacketListField("records", None, TLSRecord)]
    CONTENT_TYPE_MAP = {0x15: TLSAlert, 0x16: TLSHandshakes, 0x17: TLSPlaintext}

    def __init__(self, *args, **fields):
        self.tls_ctx = fields.pop("ctx", None)
        self._origin = fields.pop("_origin", None)
        Packet.__init__(self, *args, **fields)

    @classmethod
    def from_records(cls, records, ctx=None):
        pkt_str = "".join(list(map(str, records)))
        return cls(pkt_str, ctx)

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
        while pos < len(raw_bytes) - record_header_len:
            payload_len = record(raw_bytes[pos:pos + record_header_len]).length
            if self.tls_ctx is not None:
                payload = record(raw_bytes[pos:pos + record_header_len + payload_len], ctx=self.tls_ctx)
                # Perform inline decryption if required
                payload = self.do_decrypt_payload(payload)
                self.tls_ctx.insert(payload, origin=self._origin)
            else:
                payload = record(raw_bytes[pos:pos + record_header_len + payload_len])
            # Populate our list of found records
            records.append(payload)
            # Move to the next record
            pos += (record_header_len + payload.length)
        self.fields["records"] = records
        # This will always be empty (equivalent to returning "")
        return raw_bytes[pos:]

    def do_decrypt_payload(self, record):
        content_type = None
        encrypted_payload, layer = self._get_encrypted_payload(record)
        if encrypted_payload is not None or self.tls_ctx.negotiated.version >= TLSVersion.TLS_1_3:
            try:
                if self.tls_ctx.client:
                    cleartext = self.tls_ctx.server_ctx.crypto_ctx.decrypt(encrypted_payload,
                                                                           record.content_type)
                else:
                    cleartext = self.tls_ctx.client_ctx.crypto_ctx.decrypt(encrypted_payload,
                                                                           record.content_type)
                if self.tls_ctx.negotiated.version >= TLSVersion.TLS_1_3:
                    tag = cleartext[-self.tls_ctx.sec_params.GCM_TAG_SIZE:]
                    cleartext = cleartext[:-self.tls_ctx.sec_params.GCM_TAG_SIZE]
                    padding_index = find_padding_start(cleartext)
                    content_type = struct.unpack("B", cleartext[padding_index - 1])[0]
                    try:
                        layer = TLS.CONTENT_TYPE_MAP[content_type]
                    except KeyError:
                        raise TLSProtocolError("Decryption failed. Invalid 0x%02x content_type in payload" % content_type, response=record)
                    cleartext = "%s%s" % (cleartext, tag)
                pkt = layer(cleartext, ctx=self.tls_ctx)
                record[self.guessed_next_layer].payload = pkt
                record.content_type = content_type or record.content_type
            # Decryption failed, raise error otherwise we'll be in inconsistent state with sender
            except ValueError as ve:
                raise TLSProtocolError("Decryption failed: %s" % ve, response=record)
        return record

    def _get_encrypted_payload(self, record):
        encrypted_payload = None
        decrypted_type = None
        # TLSFinished, encrypted
        if record.haslayer(TLSRecord) and record[TLSRecord].content_type == TLSContentType.HANDSHAKE \
                and record.haslayer(TLSCiphertext):
            encrypted_payload = str(record.payload)
            decrypted_type = TLSHandshakes
        # Do not attempt to decrypt cleartext Alerts and CCS
        elif record.haslayer(TLSAlert) and record.length != 0x2:
            encrypted_payload = str(record.payload)
            decrypted_type = TLSAlert
        elif record.haslayer(TLSChangeCipherSpec) and record.length != 0x1:
            encrypted_payload = str(record.payload)
            decrypted_type = TLSChangeCipherSpec
        # Application data
        elif record.haslayer(TLSCiphertext):
            encrypted_payload = record[TLSCiphertext].data
            decrypted_type = TLSPlaintext
        return encrypted_payload, decrypted_type
TLS = SSL


def find_padding_start(payload, padding_byte=b"\x00"):
    for i, v in enumerate(payload[::-1]):
        if v != padding_byte:
            return len(payload) - i


cleartext_handler = {TLSPlaintext: lambda pkt, tls_ctx: (TLSContentType.APPLICATION_DATA, pkt[TLSPlaintext].data),
                     TLSChangeCipherSpec: lambda pkt, tls_ctx: (TLSContentType.CHANGE_CIPHER_SPEC, str(pkt[TLSChangeCipherSpec])),
                     TLSAlert: lambda pkt, tls_ctx: (TLSContentType.ALERT, str(pkt[TLSAlert])), #}
                     TLSHandshakes: lambda pkt, tls_ctx: (TLSContentType.HANDSHAKE, str(pkt[TLSHandshakes]))}


def to_raw(pkt, tls_ctx, include_record=True, compress_hook=None, pre_encrypt_hook=None, encrypt_hook=None):
    import ssl_tls_crypto as tlsc
    if tls_ctx is None:
        raise ValueError("A valid TLS session context must be provided")

    ctx = tls_ctx.client_ctx if tls_ctx.client else tls_ctx.server_ctx
    comp_method = ctx.compression

    content_type, data = None, None
    for tls_proto, handler in cleartext_handler.iteritems():
        if pkt.haslayer(tls_proto):
            content_type, data = handler(pkt[tls_proto], tls_ctx)
            break
    if content_type is None and data is None:
        raise KeyError("Unhandled encryption for TLS protocol: %s" % pkt.name)

    if compress_hook is not None:
        post_compress_data = compress_hook(comp_method, data)
    else:
        post_compress_data = comp_method.compress(data)

    factory = tlsc.CryptoContainerFactory(tls_ctx)
    crypto_data = tlsc.CryptoData.from_context(tls_ctx, ctx, post_compress_data)
    crypto_data.content_type = content_type
    crypto_container = factory.new(ctx, crypto_data)

    if pre_encrypt_hook is not None:
        crypto_container = pre_encrypt_hook(crypto_container)

    if encrypt_hook is not None:
        ciphertext = encrypt_hook(crypto_container)
    else:
        ciphertext = ctx.crypto_ctx.encrypt(crypto_container)

    if include_record:
        if tls_ctx.negotiated.version >= TLSVersion.TLS_1_3:
            tls_ciphertext = TLSRecord(content_type=TLSContentType.APPLICATION_DATA) / ciphertext
        else:
            tls_ciphertext = TLSRecord(version=tls_ctx.negotiated.version, content_type=content_type) / ciphertext
    else:
        tls_ciphertext = ciphertext

    return tls_ciphertext

tls_to_raw = to_raw


class TLSProtocolError(Exception):
    def __init__(self, *args, **kwargs):
        try:
            self.response = args[2]
        except IndexError:
            self.response = kwargs.pop("response", TLS())

        try:
            self.request = args[1]
        except IndexError:
            self.request = kwargs.pop("pkt", TLS())

        Exception.__init__(self, args[0], **kwargs)


def tls_do_round_trip(tls_socket, pkt, recv=True):
    resp = TLS()
    try:
        tls_socket.sendall(pkt)
        if recv:
            resp = tls_socket.recvall()
            if resp.haslayer(TLSAlert):
                alert = resp[TLSAlert]
                if alert.level != TLSAlertLevel.WARNING:
                    level = TLS_ALERT_LEVELS.get(alert.level, "unknown")
                    description = TLS_ALERT_DESCRIPTIONS.get(alert.description, "unknown description")
                    raise TLSProtocolError("%s alert returned by server: %s" % (level.upper(), description.upper()), pkt, resp)
    except socket.error as se:
        raise TLSProtocolError(se, pkt, resp)
    return resp


def tls_do_handshake(tls_socket, version, ciphers, extensions=[]):
    if version <= TLSVersion.TLS_1_2:
        client_hello = TLSRecord(version=version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSClientHello(version=version,
                                                                cipher_suites=ciphers,
                                                                extensions=extensions)])
        resp1 = tls_do_round_trip(tls_socket, client_hello)

        client_key_exchange = TLSRecord(version=version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        tls_socket.tls_ctx.get_client_kex_data()])
        client_ccs = TLSRecord(version=version) / TLSChangeCipherSpec()
        tls_do_round_trip(tls_socket, TLS.from_records([client_key_exchange, client_ccs]), False)

        resp2 = tls_do_round_trip(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        return resp1, resp2
    else:
        raise NotImplementedError("Do handshake not implemented for TLS 1.3")


def tls_fragment_payload(pkt, record=None, size=2**14):
    if size <= 0:
        raise ValueError("Fragment size must be strictly positive")
    payload = str(pkt)
    payloads = [payload[i: i + size] for i in range(0, len(payload), size)]
    if record is None:
        return payloads
    else:
        fragments = []
        for payload in payloads:
            fragments.append(TLSRecord(content_type=record.content_type,
                                       version=record.version,
                                       length=len(payload)) /
                             payload)
            try:
                stack = TLS.from_records(fragments, ctx=record.tls_ctx)
            except struct.error as se:
                raise TLSFragmentationError("Fragment size must be a power of 2: %s" % se)
        return stack


def tls_draft_version(draft_version):
    return 0x7f00 | draft_version


# bind magic
bind_layers(TCP, SSL, dport=443)
bind_layers(TCP, SSL, sport=443)
bind_layers(UDP, SSL, dport=4433)
bind_layers(UDP, SSL, sport=4433)

# TLSRecord
bind_layers(TLSRecord, TLSChangeCipherSpec, {'content_type': TLSContentType.CHANGE_CIPHER_SPEC})
bind_layers(TLSRecord, TLSCiphertext, {"content_type": TLSContentType.APPLICATION_DATA})
bind_layers(TLSRecord, TLSHeartBeat, {'content_type': TLSContentType.HEARTBEAT})
bind_layers(TLSRecord, TLSAlert, {'content_type': TLSContentType.ALERT})
bind_layers(TLSRecord, TLSHandshakes, {'content_type': TLSContentType.HANDSHAKE})

# --> handshake proto
bind_layers(TLSHandshake, TLSHelloRequest, {'type': TLSHandshakeType.HELLO_REQUEST})
bind_layers(TLSHandshake, TLSClientHello, {'type': TLSHandshakeType.CLIENT_HELLO})
bind_layers(TLSHandshake, TLSServerHello, {'type': TLSHandshakeType.SERVER_HELLO})
bind_layers(TLSHandshake, TLSHelloRetryRequest, {"type": TLSHandshakeType.HELLO_RETRY_REQUEST})
bind_layers(TLSHandshake, TLSCertificateList, {'type': TLSHandshakeType.CERTIFICATE})
bind_layers(TLSHandshake, TLSServerKeyExchange, {'type': TLSHandshakeType.SERVER_KEY_EXCHANGE})
bind_layers(TLSHandshake, TLSServerHelloDone, {'type': TLSHandshakeType.SERVER_HELLO_DONE})
bind_layers(TLSHandshake, TLSClientKeyExchange, {'type': TLSHandshakeType.CLIENT_KEY_EXCHANGE})
bind_layers(TLSHandshake, TLSFinished, {'type': TLSHandshakeType.FINISHED})
bind_layers(TLSHandshake, TLSSessionTicket, {'type': TLSHandshakeType.NEWSESSIONTICKET})
bind_layers(TLSHandshake, TLSCertificateRequest, {"type": TLSHandshakeType.CERTIFICATE_REQUEST})
bind_layers(TLSHandshake, TLSCertificateVerify, {"type": TLSHandshakeType.CERTIFICATE_VERIFY})
bind_layers(TLSHandshake, TLSEncryptedExtensions, {"type": TLSHandshakeType.ENCRYPTED_EXTENSIONS})
# <---

# --> extensions
bind_layers(TLSExtension, TLSExtServerNameIndication, {'type': TLSExtensionType.SERVER_NAME})
bind_layers(TLSExtension, TLSExtMaxFragmentLength, {'type': TLSExtensionType.MAX_FRAGMENT_LENGTH})
bind_layers(TLSExtension, TLSExtCertificateURL, {'type': TLSExtensionType.CLIENT_CERTIFICATE_URL})
bind_layers(TLSExtension, TLSExtECPointsFormat, {'type': TLSExtensionType.EC_POINT_FORMATS})
bind_layers(TLSExtension, TLSExtSupportedGroups, {'type': TLSExtensionType.SUPPORTED_GROUPS})
bind_layers(TLSExtension, TLSExtALPN, {'type': TLSExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION})
bind_layers(TLSExtension, TLSExtHeartbeat, {'type': TLSExtensionType.HEARTBEAT})
bind_layers(TLSExtension, TLSExtSessionTicketTLS, {'type': TLSExtensionType.SESSIONTICKET_TLS})
bind_layers(TLSExtension, TLSExtRenegotiationInfo, {'type': TLSExtensionType.RENEGOTIATION_INFO})
bind_layers(TLSExtension, TLSExtSignatureAlgorithms, {'type': TLSExtensionType.SIGNATURE_ALGORITHMS})
bind_layers(TLSExtension, TLSExtSupportedVersions, {'type': TLSExtensionType.SUPPORTED_VERSIONS})
bind_layers(TLSExtension, TLSExtCookie, {'type': TLSExtensionType.COOKIE})
bind_layers(TLSExtension, TLSExtKeyShare, {'type': TLSExtensionType.KEY_SHARE})
bind_layers(TLSExtension, TLSExtPadding, {'type': TLSExtensionType.PADDING})
bind_layers(TLSExtension, TLSExtPSKKeyExchangeModes, {'type': TLSExtensionType.PSK_KEY_EXCHANGE_MODES})
bind_layers(TLSExtension, TLSExtCertificateStatusRequest, {'type': TLSExtensionType.STATUS_REQUEST})
bind_layers(TLSExtension, TLSExtPreSharedKey, {'type': TLSExtensionType.PRE_SHARED_KEY})
# <--

# DTLSRecord
bind_layers(DTLSRecord, DTLSHandshake, {'content_type': TLSContentType.HANDSHAKE})
bind_layers(DTLSHandshake, DTLSClientHello, {'type': TLSHandshakeType.CLIENT_HELLO})

# SSLv2
bind_layers(SSLv2Record, SSLv2ServerHello, {'content_type': SSLv2MessageType.SERVER_HELLO})
bind_layers(SSLv2Record, SSLv2ClientHello, {'content_type': SSLv2MessageType.CLIENT_HELLO})
bind_layers(SSLv2Record, SSLv2ClientMasterKey, {'content_type': SSLv2MessageType.CLIENT_MASTER_KEY})
