#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
# http://www.secdev.org/projects/scapy/doc/build_dissect.html
from scapy.packet import Packet, bind_layers
from scapy.fields import *
from scapy.layers.inet import TCP
import os, time

class BLenField(LenField):
    def __init__(self, name, default, fmt = "I", adjust=lambda pkt,x:x, numbytes=None, length_of=None, count_of=None):
        self.name = name
        self.adjust=adjust
        self.numbytes=numbytes
        self.length_of= length_of
        self.count_of = count_of
        LenField.__init__(self, name, default, fmt)

        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
        self.sz = struct.calcsize(self.fmt) if not numbytes else numbytes
        self.owners = []
        
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        pack = struct.pack(self.fmt, self.i2m(pkt,val))
        if self.numbytes:
            pack=pack[len(pack)-self.numbytes:]
        return s+pack
    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        upack_data = s[:self.sz]
        # prepend struct.calcsize()-len(data) bytes to satisfy struct.unpack
        upack_data = '\x00'*(struct.calcsize(self.fmt)-self.sz) + upack_data
            
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, upack_data)[0])
    
    def i2m(self, pkt, x):
        if x is None:
            if not (self.length_of or self.count_of):
                 x = len(pkt.payload)
                 return x
             
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld,fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt,f)
        return x


TLS_VERSIONS = {0x0300:"SSL_3_0",
                  0x0301:"TLS_1_0",
                  0x0302:"TLS_1_1",
                  0x0303:"TLS_1_2"}

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
                        0x20:"finished",
                        0x21:"certificate_url",
                        0x22:"certificate_stats",
                        0xff:"unknown"}

class TLSRecord(Packet):
    name = "TLS Record"
    fields_desc = [ByteEnumField("content_type", 0xff, TLS_CONTENT_TYPES),
                   ShortEnumField("version", 0x0301, TLS_VERSIONS),
                   LenField("length",None, fmt="!H"),]
    
class TLSHandshake(Packet):
    name = "TLS Handshake"
    fields_desc = [ByteEnumField("type", 0xff, TLS_HANDSHAKE_TYPES),
                   BLenField("length",None, fmt="!I", numbytes=3),]



class TLSClientHello(Packet):
    name = "TLS Client Hello"
    fields_desc = [ShortEnumField("version", 0x0301, TLS_VERSIONS),
                   IntField("gmt_unix_time",int(time.time())),
                   StrFixedLenField("random_bytes",os.urandom(28),28),
                   FieldLenField("sessionid_length",None,length_of="sessionid",fmt="B"),
                   StrLenField("sessionid",None,length_from=lambda x:x.sessionid_length),
                   
                   FieldLenField("cipher_suites_length",None,length_of="cipher_suites",fmt="H"),
                   FieldListField("cipher_suites",None,TLSRecord(),length_from="cipher_suites_length"),
                   FieldLenField("compression_methods_length",None,length_of="compression_methods",fmt="B"),
                   FieldListField("compression_methods",None,TLSRecord(),length_from="compression_methods_length"),
                   FieldLenField("extensions_length",None,length_of="extensions",fmt="H"),
                   FieldListField("extensions",None,TLSRecord(),length_from="extensions_length"),
                   ]
    
TLS_CIPHER_SUITES = {   
    0x0000:"NULL_WITH_NULL_NULL",
    0x0001:"RSA_WITH_NULL_MD5",
    0x0002:"RSA_WITH_NULL_SHA1",
    0x003b:"RSA_WITH_NULL_SHA256",
    0x000a:"RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016:"DHE_RSA_WITH_3DES_EDE_CBC_SHA",    
    0x0013:"DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x000a:"RSA_WITH_3DES_EDE_CBC_SHA",
    0x0033:"DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0032:"DHE_DSS_WITH_AES_128_CBC_SHA",
    0x002f:"RSA_WITH_AES_128_CBC_SHA",
    0x0007:"RSA_WITH_IDEA_CBC_SHA",
    0x0066:"DHE_DSS_WITH_RC4_128_SHA",
    0x0005:"RSA_WITH_RC4_128_SHA",
    0x0004:"RSA_WITH_RC4_128_MD5",
    0x0063:"DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
    0x0062:"RSA_EXPORT1024_WITH_DES_CBC_SHA",
    0x0061:"RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
    0x0015:"DHE_RSA_WITH_DES_CBC_SHA",
    0x0012:"DHE_DSS_WITH_DES_CBC_SHA",
    0x0009:"RSA_WITH_DES_CBC_SHA",
    0x0065:"DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
    0x0064:"RSA_EXPORT1024_WITH_RC4_56_SHA",
    0x0060:"RSA_EXPORT1024_WITH_RC4_56_MD5",
    0x0014:"DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0011:"DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x0008:"RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0006:"RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0003:"RSA_EXPORT_WITH_RC4_40_MD5",
    0x0035:"RSA_WITH_AES_256_CBC_SHA",
    0x0038:"DHE_DSS_WITH_AES_256_CBC_SHA",    
    0x0039:"DHE_RSA_WITH_AES_256_CBC_SHA",
    0xc00a:"ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xc00f:"ECDH_RSA_WITH_AES_256_CBC_SHA",    
    0xc014:"ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc021:"SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    0xc022:"SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    0x0087:"DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x0088:"DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0xc005:"ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0x0084:"RSA_WITH_CAMELLIA_256_CBC_SHA",}
TLS_COMPRESSION_METHODS={
                         0x00:"COMPRESS_NULL",
                         0x01:"COMPRESS_DEFLATE",
                         }
    
class TLSServerHello(Packet):
    name = "TLS Server Hello"
    fields_desc = [ShortEnumField("version", 0x0301, TLS_VERSIONS),
                   IntField("gmt_unix_time",int(time.time())),
                   StrFixedLenField("random_bytes",os.urandom(28),28),
                   FieldLenField("sessionid_length",None,length_of="sessionid",fmt="B"),
                   StrLenField("sessionid",None,length_from=lambda x:x.sessionid_length),
                   
                   ShortEnumField("cipher_suite", 0x0000, TLS_CIPHER_SUITES),
                   ByteEnumField("compression_method", 0x00, TLS_COMPRESSION_METHODS),


                   FieldLenField("extensions_length",None,length_of="extensions",fmt="H"),
                   FieldListField("extensions",None,TLSRecord(),length_from="extensions_length"),
                   ]

TLS_ALERT_LEVELS = { 0x01: "warning",
                     0x02: "fatal",
                     0xff: "unknwon",}

TLS_ALERT_DESCRIPTIONS = {    
                    0:"CLOSE_NOTIFY",
                    10:"UNEXPECTE_MESSAGE",
                    20:"BAD_RECORD_MAC",
                    21:"DESCRIPTION_FAILED_RESERVED",
                    22:"RECORD_OVERFLOW",
                    30:"DECOMPRESSION_FAILUR",
                    40:"HANDSHAKE_FAILUR",
                    41:"NO_CERTIFICATE_RESERVED",
                    43:"BAD_CERTIFICATE",
                    43:"UNSUPPORTED_CERTIFICATE",
                    44:"CERTIFICATE_REVOKED",
                    45:"CERTIFICATE_EXPIRED",
                    46:"CERTIFICATE_UNKNOWN",
                    47:"ILLEGAL_PARAMETER",
                    48:"UNKNOWN_CA",
                    49:"ACCESS_DENIED",
                    50:"DECODE_ERROR",
                    51:"DECRYPT_ERROR",
                    60:"EXPORT_RESTRICTION_RESERVED",
                    70:"PROTOCOL_VERSION",
                    71:"INSUFFICIENT_SECURITY",
                    80:"INTERNAL_ERROR",
                    90:"USER_CANCELED",
                    100:"NO_RENEGOTIATION",
                    110:"UNSUPPORTED_EXTENSION",
                    255:"UNKNOWN_255",}

class TLSAlert(Packet):
    name = "TLS Alert"
    fields_desc = [ByteEnumField("level", 0xff, TLS_ALERT_LEVELS),
                  ByteEnumField("description", 0xff, TLS_ALERT_DESCRIPTIONS),
                  ]



TLS_EXTENSION_TYPES = {
                       0x0000:"SERVER_NAME",
                       0x0023:"SESSION_TICKET_TLS",
                       0x000f:"HEARTBEAT",
                       0x000f:"STATUS_REQUEST",
                       0xff01:"RENEGOTIATION_INFO",
                       0x000d:"SIGNATURE_ALGORITHMS",
                       }


class TLSServerName(Packet):
    name = "TLS Extension Servername"
    fields_desc = [ByteEnumField("type", 0x01, {0x01:"host"}),
                  FieldLenField("length",None,length_of="data",fmt="H"),
                  StrLenField("data","",length_from=lambda x:x.payload_length),
                  ]
    
class TLSServerNameList(Packet):
    name = "TLS Extension Servername List"
    fields_desc = [FieldLenField("length",None,length_of="data",fmt="H"),
                   FieldListField("server_names",None,TLSServerName(),length_from="length"),
                  ]   


class TLSExtension(Packet):
    name = "TLS Extension"
    fields_desc = [ShortEnumField("type", 0x0000, TLS_EXTENSION_TYPES),
                   FieldListField("extensions",None,TLSServerNameList(),length_from="length"),
                  ]

class TLSExtensionList(Packet):
    name = "TLS Extension List"
    fields_desc = [FieldLenField("length",None,length_of="data",fmt="H"),
                   FieldListField("extensions",None,TLSExtension(),length_from="length"),
                  ]   




        
class TLSHeartBeat(Packet):
    name = "TLS Extension HeartBeat"
    fields_desc = [ByteEnumField("type", 0x01, {0x01:"unknown"}),
                  FieldLenField("length",None,length_of="data",fmt="H"),
                  StrLenField("data","",length_from=lambda x:x.length),
                  StrLenField("padding","", length_from=lambda x: 'P'*(16-x.length)),
                  ]


class TLSServerKeyExchange(Packet):
    name = "TLS Server Key Exchange"
    fields_desc = [ BLenField("length",None, fmt="!I", numbytes=3),
                    StrLenField("data",os.urandom(329),length_from=lambda x:x.length),]

class TLSServerHelloDone(Packet):
    name = "TLS Server Hello Done"
    fields_desc = [ BLenField("length",None, fmt="!I", numbytes=3),
                    StrLenField("data","",length_from=lambda x:x.length),]
class TLSCertificate(Packet):
    name = "TLS Certificate List"
    fields_desc = [ BLenField("length",None, fmt="!I", numbytes=3),
                    StrLenField("data","",length_from=lambda x:x.length),]
    
class TLSCertificateList(Packet):
    name = "TLS Certificate List"
    fields_desc = [BLenField("length",None,length_of="data",fmt="!I", numbytes=3),
                   FieldListField("certificates",None,TLSCertificate(),length_from="length"),
                  ]   
    fields_desc = [ BLenField("length",None, fmt="!I", numbytes=3),
                    StrLenField("data","",length_from=lambda x:x.length),]



# entry class
class SSL(Packet):
    name = "SSL"
    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        try:
            raise
        except:
            pass
        return Packet.guess_payload_class(self, payload)



# bind magic
bind_layers(TCP, SSL, dport=443)
bind_layers(TLSRecord, TLSAlert, {'content_type':0x15})

bind_layers(TLSRecord, TLSHandshake, {'content_type':0x16})
# --> handshake proto
bind_layers(TLSHandshake,TLSClientHello, {'type':0x01})
bind_layers(TLSHandshake,TLSServerHello, {'type':0x02})
# <---
#bind_layers(TLSRecord, TLSChangeCipherSpec, {'content_type':0x17})
bind_layers(TLSRecord, TLSHeartBeat, {'content_type':0x18})



