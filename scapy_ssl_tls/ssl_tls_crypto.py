#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : <github.com/tintinweb/scapy-ssl_tls>

from __future__ import division
import binascii
import copy
import os
import struct
import zlib
import re
import warnings

import math

import pkcs7
import ssl_tls as tls
import ssl_tls_keystore as tlsk
import tinyec.ec as ec
import tinyec.registry as ec_reg

from collections import namedtuple
from Cryptodome.Cipher import AES, ARC2, ARC4, DES, DES3, PKCS1_v1_5
from Cryptodome.Hash import HMAC, MD5, SHA, SHA256, SHA384
from Cryptodome.PublicKey import DSA, RSA
from Cryptodome.Signature import PKCS1_v1_5 as Sig_PKCS1_v1_5
from scapy.packet import Raw

# Added this to get all certificate dissection to work OK, without the need to import this in the client script
# See: #PR31
# Do not move this under ssl_tls.py, it will break one UT. I have no clue as to why
from scapy.all import conf
"""
https://tools.ietf.org/html/rfc4346#section-6.3
    key_block = PRF(SecurityParameters.master_secret,
                          "key expansion",
                          SecurityParameters.server_random +
             SecurityParameters.client_random

      client_write_MAC_secret[SecurityParameters.hash_size]
       server_write_MAC_secret[SecurityParameters.hash_size]
       client_write_key[SecurityParameters.key_material_length]
       server_write_key[SecurityParameters.key_material_length]
"""

REX_PEM = re.compile(r"(\-+BEGIN\s*([^\-]+)\-+(.*?)\-+END[^\-]+\-+)", re.DOTALL)


def pem_get_objects(data):
    d = {}
    for full, pemtype, pemdata in REX_PEM.findall(data):
        d[pemtype] = {"data": data,
                      "full": full}
    return d


class TLSContext(object):

    def __init__(self, name):
        self.name = name
        self.handshake = None
        self.sequence = 0
        self.nonce = 0
        self.random = None
        self.session_id = None
        self.crypto_ctx = None
        self.compression = NullCompression
        self.finished_secret = None
        self.finished_hashes = []
        self.shares = []
        self.sym_keystore_history = []
        self.asym_keystore = tlsk.EmptyAsymKeystore()
        self.kex_keystore = tlsk.EmptyKexKeystore()
        self.__sym_keystore = tlsk.EmptySymKeyStore()
        self.must_encrypt = False

    @property
    def sym_keystore(self):
        return self.__sym_keystore

    @sym_keystore.setter
    def sym_keystore(self, value):
        if value not in self.sym_keystore_history:
            self.sym_keystore_history.append(value)
        self.__sym_keystore = value

    def load_rsa_keys_from_file(self, key_file, client=False):
        with open(key_file, "r") as f:
            # _rsa_load_keys expects one pem/der key per file.
            pemo = pem_get_objects(f.read())
            for key_pk in (k for k in pemo.keys() if "PRIVATE" in k.upper()):
                try:
                    self.asym_keystore = tlsk.RSAKeystore.from_private(pemo[key_pk].get("full"))
                    return
                except ValueError:
                    pass
        raise ValueError("Unable to load PRIVATE key from pem file: %s" % key_file)

    def load_rsa_keys(self, private):
        self.asym_keystore = tlsk.RSAKeystore.from_private(private)

    def compute_cert_verify(self, message, sig=Sig_PKCS1_v1_5, digest=SHA256):
        if self.asym_keystore.private is None:
            raise RuntimeError("Cannot sign, missing private key. Did you install an ASYM keystore?")
        return sig.new(self.asym_keystore.private).sign(digest.new(message))

    def __str__(self):
        template = """
    {name}:
        random: {random}
        session id: {sess_id}
        shares:
            {shares}
        finished:
            secret: {secret}
            finished hashes: {macs}
        {asym_ks}
        {kex_ks}
        {sym_ks}
        symetric keystore history:
            {sym_history}"""
        flatten_list = lambda list_, func: "\n".join([func(x) for x in list_]) if list_ != [] else ""
        return template.format(name=self.name, random=repr(self.random), sess_id=repr(self.session_id),
                               shares=flatten_list(self.shares, str),
                               secret=repr(self.finished_secret), macs=flatten_list(self.finished_hashes, repr),
                               asym_ks=self.asym_keystore, kex_ks=self.kex_keystore, sym_ks=self.sym_keystore,
                               sym_history=flatten_list(self.sym_keystore_history, str))


class TLSSessionCtx(object):

    def __init__(self, client=True):
        self.client = client
        self.server = not self.client
        self.client_ctx = TLSContext("Client TLS context")
        self.server_ctx = TLSContext("Server TLS context")

        # packet history
        self.history = []
        self.requires_iv = False
        self.sec_params = None
        self.cipher_properties = {}
        self.negotiated = namedtuple("negotiated", ["ciphersuite", "key_exchange", "encryption", "mac", "compression",
                                                    "compression_algo", "version", "sig", "resumption"])
        self.negotiated.ciphersuite = None
        self.negotiated.key_exchange = None
        self.negotiated.encryption = None
        self.negotiated.mac = None
        self.negotiated.compression = None
        self.negotiated.compression_algo = None
        self.negotiated.version = None
        self.negotiated.sig = None
        self.negotiated.resumption = False

        self.ticket = None
        self.encrypted_premaster_secret = None
        self.premaster_secret = None
        self.master_secret = None

        self.group_secret = None
        self.early_secrets = None
        self.handshake_secrets = None
        self.master_secrets = None
        self.resumption_secret = None

        self.prf = None

        self.__finish_count = 0
        self.__ccs_count = 0

    def __str__(self):
        template = """
TLS Session Context:
    negotiated.version: {version}
    negotiated.ciphersuite: {cipher}
    negotiated.key_exchange: {kex}
    negotiated.encryption: {enc}
    negotiated.mac: {hmac}
    negotiated.compression: {comp}
    negotiated.resumption: {resume}
    ticket: {ticket}
    encrypted_premaster_secret: {epms}
    premaster_secret: {pms}
    master_secret: {ms}
    early_secrets: {early_secrets}
    handshake_secrets: {handshake_secrets}
    master_secrets: {master_secrets}
    resumption_secret: {resumption_secret}
    {client_ctx}
    {server_ctx}"""
        return template.format(version=tls.TLS_VERSIONS.get(self.negotiated.version, "UNKNOWN"),
                               cipher=tls.TLS_CIPHER_SUITES.get(self.negotiated.ciphersuite, "UNKNOWN"),
                               kex=self.negotiated.key_exchange, enc=self.negotiated.encryption,
                               hmac=self.negotiated.mac,
                               comp=tls.TLS_COMPRESSION_METHODS.get(self.negotiated.compression, tls.TLSCompressionMethod.NULL),
                               resume=self.negotiated.resumption, epms=repr(self.encrypted_premaster_secret),
                               pms=repr(self.premaster_secret), ms=repr(self.master_secret), early_secrets=self.early_secrets,
                               handshake_secrets=self.handshake_secrets, master_secrets=self.master_secrets,
                               resumption_secret=repr(self.resumption_secret), client_ctx=self.client_ctx,
                               server_ctx=self.server_ctx,
                               ticket=repr(self.ticket))

    def insert(self, pkt, origin=None):
        """
        add packet to context
        - unpack SSL.records and add them to history
        """
        if pkt.haslayer(tls.SSL):
            ps = pkt[tls.SSL].records
        else:
            ps = [pkt]

        for pkt in ps:
            self.history.append(pkt)
            self._process(pkt, origin=origin)

    def __handle_client_hello(self, client_hello):
        # Update client context with random, session_id and generate a dummy PMS
        self.client_ctx.handshake = client_hello
        self.client_ctx.session_id = client_hello.session_id
        self.client_ctx.random = struct.pack("!I", client_hello.gmt_unix_time) + client_hello.random_bytes
        # This is a TLS 1.3 hello, retrieve and store key shares
        if client_hello.haslayer(tls.TLSExtSupportedVersions):
            # TODO: If psks are used, initialize the PRF here
            if client_hello.haslayer(tls.TLSClientHelloKeyShare):
                client_shares = client_hello[tls.TLSClientHelloKeyShare].client_shares
                for client_share in client_shares:
                    is_user_keystore = False
                    keystore = tlsk.tls_group_to_keystore(client_share.named_group, client_share.key_exchange)
                    # Check if user has already inserted a keystore for the given group
                    # If so do not replace it, since that would remove the private key
                    for share in self.client_ctx.shares:
                        if keystore.curve == share.curve:
                            is_user_keystore = True
                            break
                    if not is_user_keystore:
                        self.client_ctx.shares.append(keystore)
        else:
            # Generate a random PMS. Overriden at decryption time if private key is provided
            if self.premaster_secret is None:
                self.premaster_secret = self._generate_random_pms(client_hello.version)

    def __handle_tls12_server_hello(self, server_hello):
        self.server_ctx.session_id = server_hello.session_id
        self.server_ctx.random = struct.pack("!I", server_hello.gmt_unix_time) + server_hello.random_bytes
        # Extract all information relating to the negotiated session

        self.negotiated.compression = server_hello.compression_method
        try:
            self.negotiated.compression_algo = TLSCompressionParameters.comp_params[self.negotiated.compression]["name"]
            self.server_ctx.compression = TLSCompressionParameters.comp_params[self.negotiated.compression]["type"]
            self.client_ctx.compression = TLSCompressionParameters.comp_params[self.negotiated.compression]["type"]
        except KeyError:
            warnings.warn("Compression method 0x%02x not supported. Compression operations will fail" %
                          self.negotiated.compression)

        self.negotiated.key_exchange = self.cipher_properties["key_exchange"]["name"]
        self.negotiated.sig = self.cipher_properties["key_exchange"]["sig"]
        self.negotiated.mac = self.cipher_properties["hash"]["name"]

        self.prf = TLSPRF(self.negotiated.version, self.cipher_properties.get("prf", {}).get("type"))

        if self.negotiated.resumption:
            self.sec_params = TLSSecurityParameters.from_master_secret(self.prf,
                                                                       self.negotiated.ciphersuite,
                                                                       self.master_secret,
                                                                       self.client_ctx.random,
                                                                       self.server_ctx.random)
            self.__generate_secrets()

    def __handle_tls13_server_hello(self, server_hello):
        self.server_ctx.random = server_hello.random

        if server_hello.haslayer(tls.TLSServerHelloKeyShare):
            server_share = server_hello[tls.TLSServerHelloKeyShare].server_share
            if isinstance(self.server_ctx.kex_keystore, tlsk.EmptyKexKeystore):
                self.server_ctx.kex_keystore = tlsk.tls_group_to_keystore(server_share.named_group, server_share.key_exchange)
            keyshare_match = False
            for share in self.client_ctx.shares:
                if self.server_ctx.kex_keystore.curve == share.curve:
                    keyshare_match = True
                    self.client_ctx.kex_keystore = share
                    try:
                        secret_point = ec.ECDH(self.client_ctx.kex_keystore.keys).get_secret(self.server_ctx.kex_keystore.keys)
                    except ValueError as ve:
                        warnings.warn("Did you install a KEX keystore?: %s" % ve)
                    else:
                        # PMS is x coordinate of secret
                        self.group_secret = tlsk.int_to_str(secret_point.x)
                        prf = TLSSecurityParameters.crypto_params[self.negotiated.ciphersuite].get("prf")
                        if prf is None:
                            raise tls.TLSProtocolError("Trying to use a TLS 1.3 cipher without a defined PRF", response=server_hello)

                        self.prf = TLS13PRF(prf["type"])
                        self.sec_params = TLSSecurityParameters(self.prf, self.negotiated.ciphersuite, self.client_ctx.random, self.server_ctx.random)
                        cipher = TLSSecurityParameters.crypto_params[self.negotiated.ciphersuite]["cipher"]
                        self.early_secrets = self.prf.derive_early_secrets(client_hello_hash=self.get_handshake_hash(self.prf.digest, tls.TLSClientHello))

                        self.handshake_secrets = self.prf.derive_handshake_secrets(self.group_secret, self.early_secrets.early_secret,
                                                                                   self.get_handshake_hash(self.prf.digest, tls.TLSServerHello), cipher)
                        self.client_ctx.finished_secret = self.prf.derive_finish_secret(self.handshake_secrets.client.secret)
                        self.server_ctx.finished_secret = self.prf.derive_finish_secret(self.handshake_secrets.server.secret)
                        self.client_ctx.sym_keystore = tlsk.CipherKeyStore(self.cipher_properties, self.handshake_secrets.client.write_key,
                                                                           iv=self.handshake_secrets.client.write_iv)
                        self.server_ctx.sym_keystore = tlsk.CipherKeyStore(self.cipher_properties, self.handshake_secrets.server.write_key,
                                                                           iv=self.handshake_secrets.server.write_iv)
                        factory = CryptoContextFactory(self)
                        self.client_ctx.crypto_ctx = factory.new(self.client_ctx)
                        self.server_ctx.crypto_ctx = factory.new(self.server_ctx)
                        self.client_ctx.must_encrypt = True
                        self.server_ctx.must_encrypt = True
            if not keyshare_match:
                raise tls.TLSProtocolError("No keyshare match between client and server")
        else:
            raise tls.TLSProtocolError("TLS 1.3 server hello without KeyShare extension")

    def __handle_server_hello(self, server_hello):
        # Update the server context with random, session_id
        self.server_ctx.handshake = server_hello
        self.negotiated.version = server_hello.version
        self.negotiated.ciphersuite = server_hello.cipher_suite
        try:
            self.cipher_properties = TLSSecurityParameters.crypto_params[self.negotiated.ciphersuite]
        except KeyError:
            raise RuntimeError("Unsupported cipher: 0x%04x => %s" % (self.negotiated.ciphersuite,
                                                                     tls.TLS_CIPHER_SUITES.get(self.negotiated.ciphersuite, "UNKNOWN")))
        self.negotiated.encryption = (self.cipher_properties["cipher"]["name"], self.cipher_properties["cipher"]["key_len"],
                                      self.cipher_properties["cipher"]["mode_name"])
        self.requires_iv = True if tls.TLSVersion.TLS_1_0 < self.negotiated.version < tls.TLSVersion.TLS_1_3 else False

        if self.negotiated.version < tls.TLSVersion.TLS_1_3:
            self.__handle_tls12_server_hello(server_hello)
        # TlS 1.3 case. Extract KEX data from KeyShare extension
        else:
            self.__handle_tls13_server_hello(server_hello)

    def __handle_cert_list(self, cert_list):
        if self.negotiated.key_exchange is not None and (
                self.negotiated.key_exchange == tls.TLSKexNames.RSA or self.negotiated.sig == RSA):
            # fetch server pubkey // PKCS1_v1_5
            cert = cert_list.certificates[0].data
            # If we have a default keystore, create an RSA keystore and populate it from data on the wire
            if isinstance(self.server_ctx.asym_keystore, tlsk.EmptyAsymKeystore):
                self.server_ctx.asym_keystore = tlsk.RSAKeystore.from_der_certificate(str(cert))
            # Else keystore was assigned by user. Just add cert from the wire to the store
            else:
                self.server_ctx.asym_keystore.certificate = str(cert)
        # TODO: Handle DSA sig key loading here to allow sig checks
        elif self.negotiated.key_exchange is not None and self.negotiated.sig == DSA:
            # Pycryptodoesn't currently have an interface to this.
            # Filed bug https://github.com/dlitz/pycrypto/issues/137
            # Pycryptodome has this interface. Implement after #74
            pass
        # TODO: In the future also handle kex = DH/ECDH and extract static DH/ECDH params from cert

    def __handle_server_kex(self, server_kex):
        # DHE case
        if server_kex.haslayer(tls.TLSServerDHParams):
            if isinstance(self.server_ctx.kex_keystore, tlsk.EmptyKexKeystore):
                p = tlsk.str_to_int(server_kex[tls.TLSServerDHParams].p)
                g = tlsk.str_to_int(server_kex[tls.TLSServerDHParams].g)
                public = tlsk.str_to_int(server_kex[tls.TLSServerDHParams].y_s)
                self.server_ctx.kex_keystore = tlsk.DHKeyStore(g, p, public)
        elif server_kex.haslayer(tls.TLSServerECDHParams):
            if isinstance(self.server_ctx.kex_keystore, tlsk.EmptyKexKeystore):
                try:
                    curve_id = server_kex[tls.TLSServerECDHParams].curve_name
                    # TODO: DO NOT assume uncompressed EC points!
                    point = tlsk.ansi_str_to_point(server_kex[tls.TLSServerECDHParams].p)
                    curve_name = tls.TLS_SUPPORTED_GROUPS[curve_id]
                # Unknown curve case. Just record raw values, but do nothing with them
                except KeyError:
                    self.server_ctx.kex_keystore = tlsk.ECDHKeyStore(None, point)
                    warnings.warn("Unknown elliptic curve id: %d. Client KEX calculation is up to you" % curve_id)
                # We are on a known curve
                else:
                    try:
                        curve = ec_reg.get_curve(curve_name)
                        self.server_ctx.kex_keystore = tlsk.ECDHKeyStore(curve, ec.Point(curve, *point))
                    except ValueError:
                        self.server_ctx.kex_keystore = tlsk.ECDHKeyStore(None, point)
                        warnings.warn("Unsupported elliptic curve: %s" % curve_name)
        else:
            warnings.warn("Unknown server key exchange")

    def __handle_client_kex(self, client_kex):
        # Walk around a bug where tls_ctx is not defined, thus prevents correct parsing
        # of the TLSKeyExchange by the upper layer. Dodgy, but I don't see anyway around it
        if client_kex.haslayer(Raw):
            # Note (tin): client_kex[Raw] is short length+ data[length]
            if self.negotiated.key_exchange == tls.TLSKexNames.DHE:
                client_kex = tls.TLSClientDHParams(client_kex[Raw].load)
            elif self.negotiated.key_exchange == tls.TLSKexNames.RSA:
                client_kex = tls.TLSClientRSAParams(client_kex[Raw].load)

        if client_kex.haslayer(tls.TLSClientRSAParams):
            self.encrypted_premaster_secret = client_kex[tls.TLSClientRSAParams].data
            # If we have the private key, let's decrypt the PMS
            private = self.server_ctx.asym_keystore.private
            if private is not None:
                # I have no clue why pycrypto started failing after refactoring, missing this function
                # Probably related to https://github.com/dlitz/pycrypto/issues/160
                # TODO: workaround for now... Find root cause of pycrypto bug
                from Cryptodome import Random
                private._randfunc = Random.new().read
                # End workaround
                self.premaster_secret = PKCS1_v1_5.new(private).decrypt(self.encrypted_premaster_secret, None)
        elif client_kex.haslayer(tls.TLSClientDHParams):
            # Check if we have an unitialized keystore, and if so build a new one
            if isinstance(self.client_ctx.kex_keystore, tlsk.EmptyKexKeystore):
                server_kex_keystore = self.server_ctx.kex_keystore
                # Check if server side is a DH keystore. Something is messed up otherwise
                if isinstance(server_kex_keystore, tlsk.DHKeyStore):
                    client_public = tlsk.str_to_int(client_kex[tls.TLSClientDHParams].data)
                    self.client_ctx.kex_keystore = tlsk.DHKeyStore(server_kex_keystore.g,
                                                                   server_kex_keystore.p, client_public)
                else:
                    raise RuntimeError("Server keystore is not a DH keystore")
            pms = None
            if isinstance(self.server_ctx.kex_keystore, tlsk.DHKeyStore) and isinstance(self.client_ctx.kex_keystore, tlsk.DHKeyStore):
                if self.server_ctx.kex_keystore.private is not None:
                    pms = self.server_ctx.kex_keystore.get_psk(self.client_ctx.kex_keystore.public)
                if self.client_ctx.kex_keystore.private is not None:
                    pms = self.client_ctx.kex_keystore.get_psk(self.server_ctx.kex_keystore.public)
            if pms is None:
                raise RuntimeError("No DH private key in client or server DH Keystore")
            # Per RFC 4346 section 8.1.2
            # Leading bytes of Z that contain all zero bits are stripped before it is used as the
            # pre_master_secret.
            self.premaster_secret = tlsk.int_to_str(pms).lstrip("\x00")
        elif client_kex.haslayer(tls.TLSClientECDHParams):
            # Check if we have an unitialized keystore, and if so build a new one
            if isinstance(self.client_ctx.kex_keystore, tlsk.EmptyKexKeystore):
                server_kex_keystore = self.server_ctx.kex_keystore
                # Check if server side is a ECDH keystore. Something is messed up otherwise
                if isinstance(server_kex_keystore, tlsk.ECDHKeyStore):
                    curve = server_kex_keystore.curve
                    point = tlsk.ansi_str_to_point(client_kex[tls.TLSClientECDHParams].data)
                    self.client_ctx.kex_keystore = tlsk.ECDHKeyStore(curve, ec.Point(curve, *point))
                # TODO: Calculate PMS
        else:
            warnings.warn("Unknown client key exchange")
        self.sec_params = TLSSecurityParameters.from_pre_master_secret(self.prf, self.negotiated.ciphersuite,
                                                                       self.premaster_secret, self.client_ctx.random,
                                                                       self.server_ctx.random)
        self.__generate_secrets()

    def __handle_ccs(self, ccs, origin):
        if origin:
            # if origin was specified, mark the according ctx as must_encrypt
            # Note: abbreviated handshake: server CCS first, client CCS seconds
            # this should work in all cases where origin information is available
            if origin == "client":
                self.client_ctx.must_encrypt = True
                self.__ccs_count += 1
                return
            elif origin == "server":
                self.server_ctx.must_encrypt = True
                self.__ccs_count += 1
                return
        # origin not set, or invalid. 
        # for full handshake: client CCS received first, server second. 
        if self.__ccs_count == 0:
            self.client_ctx.must_encrypt = True
        else:
            self.server_ctx.must_encrypt = True
        self.__ccs_count += 1

    def __handle_finished(self, finished):
        if self.negotiated.version >= tls.TLSVersion.TLS_1_3:
            ctx = self.client_ctx
            verify_data = self.derive_client_finished()
            # This is the first finished in the connection, coming from the server. Transition to traffic secrets
            if self.__finish_count == 0:
                ctx = self.server_ctx
                verify_data = self.derive_server_finished()
                self.master_secrets = self.prf.derive_traffic_secrets(self.handshake_secrets.handshake_secret, self.get_handshake_hash(self.prf.digest),
                                                                      self.cipher_properties["cipher"])
                ctx.sequence = 0
                ctx.sym_keystore = tlsk.CipherKeyStore(self.cipher_properties, self.master_secrets.server.write_key,
                                                       iv=self.master_secrets.server.write_iv)
            # First client finished. Transition to traffic secrets
            elif self.__finish_count == 1:
                ctx.sequence = 0
                ctx.sym_keystore = tlsk.CipherKeyStore(self.cipher_properties, self.master_secrets.client.write_key,
                                                       iv=self.master_secrets.client.write_iv)

            ctx.finished_hashes.append(finished.data)
            if finished.data != verify_data and finished.data != "":
                warnings.warn("Finished hash does not match. Wanted %s, got %s" % (repr(verify_data), repr(finished.data)))
        self.__finish_count += 1

    def __handle_session_ticket(self, handshake):
        if handshake.haslayer(tls.TLSSessionTicket):
            # server provided ticket, lifetime..
            self.ticket = handshake[tls.TLSSessionTicket]
        elif handshake.haslayer(tls.TLSExtSessionTicketTLS):
            # client provided raw session ticket
            self.ticket = tls.TLSSessionTicket(ticket=handshake[tls.TLSExtSessionTicketTLS].data)

    def __generate_secrets(self):
        if isinstance(self.client_ctx.sym_keystore, tlsk.EmptySymKeyStore):
            self.client_ctx.sym_keystore = self.sec_params.client_keystore
        if isinstance(self.server_ctx.sym_keystore, tlsk.EmptySymKeyStore):
            self.server_ctx.sym_keystore = self.sec_params.server_keystore
        self.master_secret = self.sec_params.master_secret
        # Retrieve ciphers used for client/server encryption and decryption
        factory = CryptoContextFactory(self)
        self.client_ctx.crypto_ctx = factory.new(self.client_ctx)
        self.server_ctx.crypto_ctx = factory.new(self.server_ctx)

    def _process(self, pkt, origin=None):
        """
        fill context
        """
        if pkt.haslayer(tls.TLSHandshake):
            # requires handshake messages
            if pkt.haslayer(tls.TLSClientHello):
                self.__handle_client_hello(pkt[tls.TLSClientHello])
            if pkt.haslayer(tls.TLSServerHello):
                self.__handle_server_hello(pkt[tls.TLSServerHello])
            if pkt.haslayer(tls.TLSCertificateList):
                self.__handle_cert_list(pkt[tls.TLSCertificateList])
            if pkt.haslayer(tls.TLSServerKeyExchange):
                self.__handle_server_kex(pkt[tls.TLSServerKeyExchange])
            if pkt.haslayer(tls.TLSClientKeyExchange):
                self.__handle_client_kex(pkt[tls.TLSClientKeyExchange])
            if pkt.haslayer(tls.TLSFinished):
                self.__handle_finished(pkt[tls.TLSFinished])
            self.__handle_session_ticket(pkt)
        if pkt.haslayer(tls.TLSChangeCipherSpec):
            self.__handle_ccs(pkt[tls.TLSChangeCipherSpec], origin=origin)

    def _generate_random_pms(self, version):
        return "%s%s" % (struct.pack("!H", version), os.urandom(46))

    def get_encrypted_pms(self, pms=None):
        cleartext = pms or self.premaster_secret
        public = self.server_ctx.asym_keystore.public
        if public is not None:
            self.encrypted_premaster_secret = PKCS1_v1_5.new(public).encrypt(cleartext)
        else:
            raise ValueError("Cannot calculate encrypted MS. No server certificate found in connection")
        return self.encrypted_premaster_secret

    def get_client_dh_pubkey(self, private=None):
        if not isinstance(self.server_ctx.kex_keystore, tlsk.DHKeyStore):
            raise RuntimeError("Server keystore is not DH")
        g = self.server_ctx.kex_keystore.g
        p = self.server_ctx.kex_keystore.p
        self.client_ctx.kex_keystore = tlsk.DHKeyStore.new_keypair(g, p, private)
        return tlsk.int_to_str(self.client_ctx.kex_keystore.public)

    def get_client_ecdh_pubkey(self, private=None):
        if not isinstance(self.server_ctx.kex_keystore, tlsk.ECDHKeyStore):
            raise RuntimeError("Server keystore is not ECDH")
        if self.server_ctx.kex_keystore.unknown_curve:
            raise RuntimeError("Unknown EC. KEX calculation is up to you")

        curve = self.server_ctx.kex_keystore.curve
        server_keypair = self.server_ctx.kex_keystore.keys
        if private is None:
            client_keypair = ec.make_keypair(curve)
        else:
            client_keypair = ec.Keypair(curve, private)
        self.client_ctx.kex_keystore = tlsk.ECDHKeyStore.from_keypair(curve, client_keypair)

        secret_point = ec.ECDH(client_keypair).get_secret(server_keypair)
        # PMS is x coordinate of secret
        self.premaster_secret = tlsk.int_to_str(secret_point.x)
        return tlsk.point_to_ansi_str(client_keypair.pub)

    def get_client_kex_data(self, val=None):
        if self.negotiated.key_exchange == tls.TLSKexNames.RSA:
            return tls.TLSClientKeyExchange() / tls.TLSClientRSAParams(data=self.get_encrypted_pms(val))
        elif self.negotiated.key_exchange == tls.TLSKexNames.DHE:
            return tls.TLSClientKeyExchange() / tls.TLSClientDHParams(data=self.get_client_dh_pubkey(val))
        elif self.negotiated.key_exchange == tls.TLSKexNames.ECDHE:
            return tls.TLSClientKeyExchange() / tls.TLSClientECDHParams(data=self.get_client_ecdh_pubkey(val))
        else:
            raise NotImplementedError("Key exchange unknown or currently not supported")

    def get_server_dhe_ske(self, sig=Sig_PKCS1_v1_5, digest=SHA256):
        if self.client_ctx.random is None or self.server_ctx.random is None:
            raise ValueError("Server/client randoms cannot be none")
        if not isinstance(self.server_ctx.kex_keystore, tlsk.DHKeyStore):
            raise ValueError("Server keystore is not a DHKeystore")
        dhk = self.server_ctx.kex_keystore
        msg = "%s%s" % (self.client_ctx.random, self.server_ctx.random)
        msg += tlsk.int_to_vector(dhk.p)
        msg += tlsk.int_to_vector(dhk.g)
        msg += tlsk.int_to_vector(dhk.public)
        ske_sig = sig.new(self.server_ctx.asym_keystore.private).sign(digest.new(msg))
        # TODO: Be smart, set scheme_type based on sig and hash. This is a pain to do, so being lazy
        return tls.TLSServerDHParams(p=tlsk.int_to_str(dhk.p), g=tlsk.int_to_str(dhk.g), y_s=tlsk.int_to_str(dhk.public), sig=ske_sig)

    def _walk_handshake_msgs(self):
        for pkt in self.history:
            if pkt.haslayer(tls.TLSHandshakes):
                for handshake in pkt[tls.TLSHandshakes].handshakes:
                    if not handshake.haslayer(tls.TLSHelloRequest):
                        yield handshake

    def _derive_finished(self, secret, hash_):
        return HMAC.new(secret, hash_, digestmod=self.prf.digest).digest()

    def derive_server_finished(self):
        if self.server_ctx.finished_secret is None:
            raise ValueError("No finished secret available")
        return self._derive_finished(self.server_ctx.finished_secret, self.get_handshake_hash(self.prf.digest, tls.TLSFinished, False))

    def derive_client_finished(self):
        if self.client_ctx.finished_secret is None:
            raise ValueError("No finished secret available")
        return self._derive_finished(self.client_ctx.finished_secret, self.get_handshake_hash(self.prf.digest, tls.TLSFinished, True))

    def get_verify_data(self, data=None):
        if self.negotiated.version >= tls.TLSVersion.TLS_1_3:
            if self.client:
                prf_verify_data = self.derive_client_finished()
            else:
                prf_verify_data = self.derive_server_finished()
        else:
            if self.client:
                label = TLSPRF.TLS_MD_CLIENT_FINISH_CONST
            else:
                label = TLSPRF.TLS_MD_SERVER_FINISH_CONST
            if data is None:
                verify_data = []
                for handshake in self._walk_handshake_msgs():
                    if handshake.haslayer(tls.TLSFinished):
                        # Special case of encrypted handshake. Remove crypto material to compute verify_data
                        verify_data.append("%s%s%s" % (chr(handshake.type), struct.pack(">I", handshake.length)[1:],
                                                       handshake[tls.TLSFinished].data))
                    else:
                        verify_data.append(str(handshake))
            else:
                verify_data = [data]

            if self.negotiated.version == tls.TLSVersion.TLS_1_2:
                prf_verify_data = self.prf.get_bytes(self.master_secret, label,
                                                     self.prf.digest.new("".join(verify_data)).digest(),
                                                     num_bytes=12)
            else:
                prf_verify_data = self.prf.get_bytes(self.master_secret, label,
                                                     "%s%s" % (MD5.new("".join(verify_data)).digest(),
                                                               SHA.new("".join(verify_data)).digest()),
                                                     num_bytes=12)
        return prf_verify_data

    def get_handshake_digest(self, hash_):
        for handshake in self._walk_handshake_msgs():
            hash_.update(str(handshake))
        return hash_

    def get_handshake_hash(self, digest, up_to=None, include=True):
        digest = digest.new()
        for handshake in self._walk_handshake_msgs():
            if handshake.haslayer(up_to):
                if include:
                    digest.update(str(handshake))
                break
            digest.update(str(handshake))
        return digest.digest()

    def get_client_signed_handshake_hash(self, hash_=SHA256.new(), pre_sign_hook=lambda x: x, sig=Sig_PKCS1_v1_5):
        """Legacy way to get the certificate verify hash. Added sig as last parameter to preserve prior use"""
        if self.client_ctx.asym_keystore.private is None:
            raise RuntimeError("Missing client private key. Can't sign")
        msg_hash = self.get_handshake_digest(hash_)
        msg_hash = pre_sign_hook(msg_hash)
        # Will throw exception if we can't sign or if data is larger the modulus
        return sig.new(self.client_ctx.asym_keystore.private).sign(msg_hash)

    def _compute_cert_verify(self, ctx, hash_, label, sig=Sig_PKCS1_v1_5, digest=SHA256, pre_sign_hook=lambda x: x):
        sig_prefix = b"\x20" * 64
        # The hash of the handshake is computed over the PRF hash, NOT the sig hash
        sig_content = b"%s%s\x00%s" % (sig_prefix, label, hash_)
        # Now sign using the proper signature scheme, specified in the cert verify alg field
        return ctx.compute_cert_verify(pre_sign_hook(sig_content), sig, digest)

    def compute_server_cert_verify(self, sig=Sig_PKCS1_v1_5, digest=SHA256, pre_sign_hook=lambda x: x):
        sig_label = b"TLS 1.3, server CertificateVerify"
        if self.prf is None:
            raise RuntimeError("PRF must be initialized prior to computing TLS 1.3 signature")
        hash_ = self.get_handshake_hash(self.prf.digest, tls.TLSCertificateList)
        return self._compute_cert_verify(self.server_ctx, hash_, sig_label, sig, digest, pre_sign_hook)

    def compute_client_cert_verify(self, sig=Sig_PKCS1_v1_5, digest=SHA256, pre_sign_hook=lambda x: x):
        if self.negotiated.version >= tls.TLSVersion.TLS_1_3:
            sig_label = b"TLS 1.3, client CertificateVerify"
            if self.prf is None:
                raise RuntimeError("PRF must be initialized prior to computing TLS 1.3 signature")
            # TODO: calculate handshake hash properly until the second tls.TLSCertificateList for client based certs
            hash_ = self.get_handshake_hash(self.prf.digest, tls.TLSCertificateList)
            return self._compute_cert_verify(self.server_ctx, hash_, sig_label, sig, digest, pre_sign_hook)
        else:
            return self.get_client_signed_handshake_hash(digest.new(), pre_sign_hook, sig)

    def set_mode(self, client=None, server=None):
        self.client = client if client else not server
        self.server = not self.client

    def resume_session(self, master_secret):
        self.master_secret = master_secret
        self.negotiated.resumption = True


class TLSPRF(object):
    TLS_MD_CLIENT_FINISH_CONST = "client finished"
    TLS_MD_SERVER_FINISH_CONST = "server finished"
    TLS_MD_KEY_EXPANSION_CONST = "key expansion"
    TLS_MD_CLIENT_WRITE_KEY_CONST = "client write key"
    TLS_MD_SERVER_WRITE_KEY_CONST = "server write key"
    TLS_MD_IV_BLOCK_CONST = "IV block"
    TLS_MD_MASTER_SECRET_CONST = "master secret"

    def __init__(self, tls_version, digest=None):
        if tls_version not in tls.TLS_VERSIONS.keys():
            raise ValueError("Unknown TLS version: %d" % tls_version)
        self.tls_version = tls_version
        if self.tls_version < tls.TLSVersion.TLS_1_2 and digest is not None:
            raise ValueError("PRF digest can be set only for TLS versions 1.2 and above")
        else:
            if digest is None:
                self.digest = SHA256
            else:
                self.digest = digest

    def get_bytes(self, key, label, random, num_bytes):
        if self.tls_version >= tls.TLSVersion.TLS_1_2:
            bytes_ = self._get_bytes(self.digest, key, label, random, num_bytes)
        else:
            key_len = (len(key) + 1) // 2
            key_left = key[:key_len]
            key_right = key[-key_len:]

            # Get bytes from MD5
            md5_bytes = self._get_bytes(MD5, key_left, label, random, num_bytes)
            # Get bytes from SHA1
            sha1_bytes = self._get_bytes(SHA, key_right, label, random, num_bytes)

            xored = []
            for i in range(num_bytes):
                xored.append(chr(ord(md5_bytes[i]) ^ ord(sha1_bytes[i])))
            bytes_ = "".join(xored)
        return bytes_

    def _get_bytes(self, digest, key, label, random, num_bytes):
        bytes_ = ""
        block = HMAC.new(key=key, msg="%s%s" % (label, random), digestmod=digest).digest()
        while len(bytes_) < num_bytes:
            bytes_ += HMAC.new(key=key, msg="%s%s%s" % (block, label, random), digestmod=digest).digest()
            block = HMAC.new(key=key, msg=block, digestmod=digest).digest()
        return bytes_[:num_bytes]


class TLS13PRF(object):
    LABEL_EXTERNAL_PSK_BINDER_KEY = "external psk binder key"
    LABEL_RESUMPTION_PSK_BINDER_KEY = "resumption psk binder key"
    LABEL_EARLY_TRAFFIC_SECRET = "client early traffic secret"
    LABEL_EARLY_EXPORTER_MASTER_SECRET = "early exporter master secret"
    LABEL_CLIENT_HANDSHAKE_SECRET = "client handshake traffic secret"
    LABEL_SERVER_HANDSHAKE_SECRET = "server handshake traffic secret"
    LABEL_CLIENT_TRAFFIC_SECRET = "client application traffic secret"
    LABEL_SERVER_TRAFFIC_SECRET = "server application traffic secret"
    LABEL_EXPORTER_MASTER_SECRET = "exporter master secret"
    LABEL_RESUMPTION_MASTER_SECRET = "resumption master secret"
    LABEL_UPDATE_TRAFFIC_SECRET = "application traffic secret"
    LABEL_WRITE_KEY = "key"
    LABEL_WRITE_IV = "iv"
    LABEL_FINISHED = "finished"

    def __init__(self, digest=SHA256):
        self.digest = digest
        self.digest_size = self.digest.digest_size

    class HKDFLabel(object):
        LABEL_PREFIX = b"TLS 1.3, "

        def __init__(self, len_, label, hash_):
            self.len_ = struct.pack("!H", len_)
            if (len(label) > 255) or (len(hash_) > 255):
                raise ValueError("All values must be 255 bytes or less")
            self.label = "%s%s" % (self.LABEL_PREFIX, label)
            self.hash_ = hash_

        def __str__(self):
            return "%s%s%s%s%s" % (self.len_, struct.pack("B", len(self.label)), self.label, struct.pack("B", len(self.hash_)), self.hash_)

    class TLSPRFEarlySecrets(object):
        def __init__(self, early_secret, binder_key=b"", client_early_traffic_secret=b"", early_exporter_secret=b""):
            self.early_secret = early_secret
            self.binder_key = binder_key
            self.client_early_traffic_secret = client_early_traffic_secret
            self.early_exporter_secret = early_exporter_secret

        def __str__(self):
            template = """
        early_secret: {secret}
        binder_key: {binder_key}
        client_early_traffic_secret: {early_traffic_secret}
        early_exporter_secret: {exporter}"""
            return template.format(secret=repr(self.early_secret), binder_key=repr(self.binder_key),
                                   early_traffic_secret=repr(self.client_early_traffic_secret), exporter=repr(self.early_exporter_secret))

    class TLSPRFWriteSecrets(object):
        def __init__(self, secret, write_key, write_iv):
            self.secret = secret
            self.write_key = write_key
            self.write_iv = write_iv

        def __str__(self):
            template = """
            secret: {secret}
            write_key: {key}
            write_iv: {iv}"""
            return template.format(secret=repr(self.secret), key=repr(self.write_key), iv=repr(self.write_iv))

    class TLSPRFHandshakeSecrets(object):
        def __init__(self, handshake_secret, client_handshake_secrets, server_handshake_secrets):
            self.handshake_secret = handshake_secret
            self.client = client_handshake_secrets
            self.server = server_handshake_secrets

        def __str__(self):
            template = """
        handshake_secret: {secret}
        client_handshake_secrets: {client}
        server_handshake_secrets: {server}"""
            return template.format(secret=repr(self.handshake_secret), client=self.client, server=self.server)

    class TLSPRFTrafficSecrets(object):
        def __init__(self, master_secret, client_traffic_secrets, server_traffic_secrets, exporter_secret):
            self.master_secret = master_secret
            self.client = client_traffic_secrets
            self.server = server_traffic_secrets
            self.exporter_secret = exporter_secret

        def __str__(self):
            template = """
        master_secret: {secret}
        exporter_secret: {exporter}
        client_traffic_secrets: {client}
        server_traffic_secrets: {server}"""
            return template.format(secret=repr(self.master_secret), exporter=repr(self.exporter_secret), client=self.client, server=self.server)

    def extract(self, key, salt=None):
        return HKDF(self.digest).extract(key, salt).prk

    def expand_label(self, key, label, hash_, len_=None):
        len_ = len_ or self.digest_size
        return HKDF(self.digest).expand(len_, str(TLS13PRF.HKDFLabel(len_, label, hash_)), key)

    def derive_early_secrets(self, psk=None, client_hello_hash=b"", resumption_psk=True):
        psk = psk or "\x00" * self.digest_size
        binder_label = TLS13PRF.LABEL_RESUMPTION_PSK_BINDER_KEY if resumption_psk else TLS13PRF.LABEL_EXTERNAL_PSK_BINDER_KEY
        hkdf = HKDF(self.digest).extract(psk)
        if client_hello_hash == b"":
            return TLS13PRF.TLSPRFEarlySecrets(hkdf.prk)
        else:
            return TLS13PRF.TLSPRFEarlySecrets(hkdf.prk,
                                               self.expand_label(hkdf.prk, binder_label, b""),
                                               self.expand_label(hkdf.prk, TLS13PRF.LABEL_EARLY_TRAFFIC_SECRET, client_hello_hash),
                                               self.expand_label(hkdf.prk, TLS13PRF.LABEL_EARLY_EXPORTER_MASTER_SECRET, client_hello_hash))

    def derive_handshake_secrets(self, group_key, early_secret, hellos_hash, cipher):
        hkdf = HKDF(self.digest).extract(group_key, early_secret)
        secrets = []
        for label in [TLS13PRF.LABEL_CLIENT_HANDSHAKE_SECRET, TLS13PRF.LABEL_SERVER_HANDSHAKE_SECRET]:
            secret = self.expand_label(hkdf.prk, label, hellos_hash)
            write_secrets = self._derive_write_keys(secret, cipher)
            secrets.append(write_secrets)
        return TLS13PRF.TLSPRFHandshakeSecrets(hkdf.prk, *secrets)

    def derive_resumption_secret(self, handshake_secret, client_finish_hash):
        hkdf = HKDF(self.digest).extract(b"\x00" * self.digest_size, handshake_secret)
        return self.expand_label(hkdf.prk, TLS13PRF.LABEL_RESUMPTION_MASTER_SECRET, client_finish_hash)

    def derive_finish_secret(self, handshake_secret):
        return self.expand_label(handshake_secret, TLS13PRF.LABEL_FINISHED, b"")

    def derive_traffic_secrets(self, handshake_secret, finish_hash, cipher):
        hkdf = HKDF(self.digest).extract(b"\x00" * self.digest_size, handshake_secret)
        secrets = []
        for label in [TLS13PRF.LABEL_CLIENT_TRAFFIC_SECRET, TLS13PRF.LABEL_SERVER_TRAFFIC_SECRET]:
            secret = self.expand_label(hkdf.prk, label, finish_hash)
            write_secrets = self._derive_write_keys(secret, cipher)
            secrets.append(write_secrets)
        exporter_secret = self.expand_label(hkdf.prk, TLS13PRF.LABEL_EXPORTER_MASTER_SECRET, finish_hash)
        return TLS13PRF.TLSPRFTrafficSecrets(hkdf.prk, secrets[0], secrets[1], exporter_secret)

    def _derive_write_keys(self, secret, cipher):
        key = self.expand_label(secret, TLS13PRF.LABEL_WRITE_KEY, b"", cipher["key_len"])
        iv = self.expand_label(secret, TLS13PRF.LABEL_WRITE_IV, b"", cipher["iv_len"])
        return TLS13PRF.TLSPRFWriteSecrets(secret, key, iv)


class HKDFError(Exception):
    pass


class HKDF(object):
    def __init__(self, digest):
        if digest is None:
            raise HKDFError("Digest cannot be None")
        self.digest = digest
        self.digest_size = self.digest.digest_size
        self.prk = b""

    def extract(self, ikm, salt=None):
        if salt is None:
            salt = b"\x00" * self.digest_size
        self.prk = HMAC.new(salt, msg=ikm, digestmod=self.digest).digest()
        return self

    def expand(self, len_, info=b"", prk=None):
        # L is len_, T is bytes_ in RFC 5869
        if prk is not None:
            self.prk = prk
        if self.prk == b"":
            raise HKDFError("PRK must be derived prior to calling expand")
        if len_ > 255 * self.digest_size:
            raise HKDFError("HKDF can output at max %d bytes, but you asked for %d" % (255 * self.digest_size, len_))
        n = int(math.ceil(len_ / self.digest_size))
        block = b""
        bytes_ = b""
        for i in range(1, n + 1):
            block = HMAC.new(self.prk, "%s%s%s" % (block, info, struct.pack("B", i)), digestmod=self.digest).digest()
            bytes_ += block
        return bytes_[:len_]


class CryptoData(object):
    def __init__(self, data, sequence, version, content_type=tls.TLSContentType.APPLICATION_DATA,
                 data_len=None, padding_len=0):
        self.data = data
        self.sequence = sequence
        self.version = version
        self.content_type = content_type
        self.data_len = data_len or len(data)
        self.padding = b"\x00" * padding_len

    @classmethod
    def from_context(cls, tls_ctx, ctx, data=b""):
        return cls(data, ctx.sequence, tls_ctx.negotiated.version)

    def __str__(self):
        template = """Crypto data:
            data: {data},
            len: {len}
            sequence: {seq}
            version: {ver}
            content type: {ct}"""
        return template.format(data=repr(self.data), len=self.data_len, seq=self.sequence, ver=self.version,
                               ct=self.content_type)


class CipherMode(object):
    NULL = "NULL"
    STREAM = "STREAM"
    CBC = "CBC"
    EAEAD = "EAEAD"
    IAEAD = "IAEAD"


class CryptoContext(object):
    def __init__(self, tls_ctx, ctx, mode):
        self.tls_ctx = tls_ctx
        self.sec_params = self.tls_ctx.sec_params
        self.ctx = ctx
        self.mode = mode

    def encrypt_data(self, data):
        raise NotImplementedError()

    def encrypt(self, crypto_container):
        raise NotImplementedError()

    def decrypt(self, ciphertext):
        # TODO: Return a crypto_container
        raise NotImplementedError()


class StreamCryptoContext(CryptoContext):
    def __init__(self, tls_ctx, ctx):
        super(StreamCryptoContext, self).__init__(tls_ctx, ctx, CipherMode.STREAM)
        self.__init_ciphers()

    def __init_ciphers(self):
        self.enc_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key)
        self.dec_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key)

    def encrypt_data(self, data):
        crypto_data = CryptoData.from_context(self.tls_ctx, self.ctx, data)
        crypto_container = StreamCryptoContainer.from_context(self.tls_ctx, self.ctx, crypto_data)
        return self.encrypt(crypto_container)

    def encrypt(self, crypto_container):
        ciphertext = self.enc_cipher.encrypt(str(crypto_container))
        self.ctx.sequence += 1
        return ciphertext

    def decrypt(self, ciphertext, content_type=tls.TLSContentType.APPLICATION_DATA):
        cleartext = self.dec_cipher.decrypt(ciphertext)
        self.ctx.sequence += 1
        return cleartext


class CBCCryptoContext(CryptoContext):
    def __init__(self, tls_ctx, ctx):
        super(CBCCryptoContext, self).__init__(tls_ctx, ctx, CipherMode.CBC)
        self.explicit_iv = b""
        if self.tls_ctx.requires_iv:
            self.ctx.sym_keystore.iv = b"\x00" * self.sec_params.block_size
        else:
            self.__init_ciphers()

    def __init_ciphers(self):
        self.enc_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          IV=self.ctx.sym_keystore.iv)
        self.dec_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          IV=self.ctx.sym_keystore.iv)

    def encrypt_data(self, data):
        crypto_data = CryptoData.from_context(self.tls_ctx, self.ctx, data)
        crypto_container = CBCCryptoContainer.from_context(self.tls_ctx, self.ctx, crypto_data)
        return self.encrypt(crypto_container)

    def encrypt(self, crypto_container):
        if self.tls_ctx.requires_iv:
            self.__init_ciphers()
        ciphertext = self.enc_cipher.encrypt(str(crypto_container))
        self.ctx.sequence += 1
        return ciphertext

    def decrypt(self, ciphertext, content_type=tls.TLSContentType.APPLICATION_DATA):
        if self.tls_ctx.requires_iv:
            self.__init_ciphers()
        cleartext = self.dec_cipher.decrypt(ciphertext)
        self.ctx.sequence += 1
        return cleartext


class EAEADCryptoContext(CryptoContext):
    def __init__(self, tls_ctx, ctx):
        super(EAEADCryptoContext, self).__init__(tls_ctx, ctx, CipherMode.EAEAD)
        # Tag size is hardcoded to 128 bits in GCM for TLS
        self.tag_size = self.tls_ctx.sec_params.GCM_TAG_SIZE
        self.explicit_iv_size = self.tls_ctx.sec_params.GCM_EXPLICIT_IV_SIZE

    def __init_ciphers(self, nonce):
        self.enc_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          nonce=nonce)
        self.dec_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          nonce=nonce)

    def get_nonce(self, nonce=None):
        nonce = nonce or struct.pack("!Q", self.ctx.nonce)
        return b"%s%s" % (self.ctx.sym_keystore.iv, nonce)

    def encrypt_data(self, data):
        crypto_container = EAEADCryptoContainer.from_data(self.tls_ctx, self.ctx, data)
        return self.encrypt(crypto_container)

    def encrypt(self, crypto_container):
        self.__init_ciphers(self.get_nonce())
        self.enc_cipher.update(crypto_container.aead)
        ciphertext, mac = self.enc_cipher.encrypt_and_digest(str(crypto_container))
        bytes_ = "%s%s%s" % (struct.pack("!Q", self.ctx.nonce), ciphertext, mac)
        self.ctx.nonce += 1
        self.ctx.sequence += 1
        return bytes_

    def decrypt(self, ciphertext, content_type=tls.TLSContentType.APPLICATION_DATA):
        explicit_nonce = ciphertext[:self.explicit_iv_size]
        ciphertext, tag = ciphertext[self.explicit_iv_size:-self.tag_size], ciphertext[-self.tag_size:]
        # Create an empty Crypto container to retrieve AEAD data based on length of cleartext
        crypto_data = CryptoData.from_context(self.tls_ctx, self.ctx, "\x00" * len(ciphertext))
        crypto_data.content_type = content_type
        crypto_container = EAEADCryptoContainer.from_context(self.tls_ctx, self.ctx, crypto_data)
        self.__init_ciphers(self.get_nonce(explicit_nonce))
        self.dec_cipher.update(crypto_container.aead)
        cleartext = self.dec_cipher.decrypt(ciphertext)
        try:
            self.dec_cipher.verify(tag)
        except ValueError as why:
            warnings.warn("Verification of GCM tag failed: %s" % why)
        self.ctx.nonce = struct.unpack("!Q", explicit_nonce)[0]
        self.ctx.sequence += 1
        return "%s%s%s" % (explicit_nonce, cleartext, tag)


class IAEADCryptoContext(CryptoContext):
    def __init__(self, tls_ctx, ctx):
        super(IAEADCryptoContext, self).__init__(tls_ctx, ctx, CipherMode.IAEAD)
        # Tag size is hardcoded to 128 bits in GCM for TLS
        self.tag_size = self.tls_ctx.sec_params.GCM_TAG_SIZE

    def __init_ciphers(self, nonce):
        self.enc_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          nonce=nonce)
        self.dec_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          nonce=nonce)

    def get_nonce(self, nonce=None, sequence=None):
        iv = nonce or self.ctx.sym_keystore.iv
        # Sequence is left padded to iv length
        sequence = sequence or struct.pack("!Q", self.ctx.sequence).rjust(len(iv), b"\x00")
        if len(iv) != len(sequence):
            raise ValueError("IV and sequence length must be identical")
        return b"".join([chr(ord(v) ^ ord(iv[i])) for i, v in enumerate(sequence)])

    def encrypt_data(self, data):
        crypto_container = IAEADCryptoContainer.from_data(self.tls_ctx, self.ctx, data)
        return self.encrypt(crypto_container)

    def encrypt(self, crypto_container):
        self.__init_ciphers(self.get_nonce())
        ciphertext, mac = self.enc_cipher.encrypt_and_digest(str(crypto_container))
        bytes_ = "%s%s" % (ciphertext, mac)
        self.ctx.sequence += 1
        return bytes_

    def decrypt(self, ciphertext, content_type=tls.TLSContentType.APPLICATION_DATA):
        ciphertext, tag = ciphertext[:-self.tag_size], ciphertext[-self.tag_size:]
        self.__init_ciphers(self.get_nonce())
        cleartext = self.dec_cipher.decrypt(ciphertext)
        try:
            self.dec_cipher.verify(tag)
        except ValueError as why:
            warnings.warn("Verification of GCM tag failed: %s" % why)
        self.ctx.sequence += 1
        return "%s%s" % (cleartext, tag)


class CryptoContextFactory(object):
    crypto_context_map = {CipherMode.STREAM: StreamCryptoContext,
                          CipherMode.CBC: CBCCryptoContext,
                          CipherMode.EAEAD: EAEADCryptoContext,
                          CipherMode.IAEAD: IAEADCryptoContext}

    def __init__(self, tls_ctx):
        self.tls_ctx = tls_ctx
        self.sec_params = self.tls_ctx.sec_params
        self.cipher_mode = self.sec_params.cipher_mode_name

    def new(self, ctx):
        try:
            class_ = CryptoContextFactory.crypto_context_map[self.cipher_mode]
        except KeyError:
            raise ValueError("Unavailable cipher mode: %s" % self.cipher_mode)
        return class_(self.tls_ctx, ctx)


class CryptoContainer(object):
    def __init__(self, crypto_data, digest):
        self.crypto_data = crypto_data
        self.digest = digest

    @classmethod
    def from_context(cls, tls_ctx, ctx, crypto_data):
        raise NotImplementedError()

    def __len__(self):
        return len(str(self))


class StreamCryptoContainer(CryptoContainer):
    def __init__(self, crypto_data, digest):
        super(StreamCryptoContainer, self).__init__(crypto_data, digest)
        self.mac = b""
        self.__mac()

    @classmethod
    def from_context(cls, tls_ctx, ctx, crypto_data):
        mac = HMAC.new(ctx.sym_keystore.hmac, digestmod=tls_ctx.sec_params.hash_type)
        return cls(crypto_data, mac)

    @classmethod
    def from_data(cls, tls_ctx, ctx, data):
        crypto_data = CryptoData.from_context(tls_ctx, ctx, data)
        return StreamCryptoContainer.from_context(tls_ctx, ctx, crypto_data)

    def __mac(self):
        sequence_ = struct.pack("!Q", self.crypto_data.sequence)
        content_type_ = struct.pack("!B", self.crypto_data.content_type)
        version_ = struct.pack("!H", self.crypto_data.version)
        len_ = struct.pack("!H", self.crypto_data.data_len)
        self.digest.update("%s%s%s%s%s" % (sequence_, content_type_, version_, len_, self.crypto_data.data))
        self.mac = self.digest.digest()

    def __str__(self):
        return "%s%s" % (self.crypto_data.data, self.mac)


class CBCCryptoContainer(CryptoContainer):
    def __init__(self, crypto_data, digest, explicit_iv=b""):
        super(CBCCryptoContainer, self).__init__(crypto_data, digest)
        self.explicit_iv = explicit_iv
        self.mac = b""
        self.padding = b""
        self.pkcs7 = pkcs7.PKCS7Encoder()
        # CBC mode
        self.__mac()
        self.__pad()
        self.padding_len = chr(len(self.padding))

    @classmethod
    def from_context(cls, tls_ctx, ctx, crypto_data):
        explicit_iv = b""
        if tls_ctx.requires_iv:
            explicit_iv = os.urandom(tls_ctx.sec_params.block_size)
        mac = HMAC.new(ctx.sym_keystore.hmac, digestmod=tls_ctx.sec_params.hash_type)
        return cls(crypto_data, mac, explicit_iv)

    @classmethod
    def from_data(cls, tls_ctx, ctx, data):
        crypto_data = CryptoData.from_context(tls_ctx, ctx, data)
        return CBCCryptoContainer.from_context(tls_ctx, ctx, crypto_data)

    def __mac(self):
        sequence_ = struct.pack("!Q", self.crypto_data.sequence)
        content_type_ = struct.pack("!B", self.crypto_data.content_type)
        version_ = struct.pack("!H", self.crypto_data.version)
        len_ = struct.pack("!H", self.crypto_data.data_len)
        self.digest.update("%s%s%s%s%s" % (sequence_, content_type_, version_, len_, self.crypto_data.data))
        self.mac = self.digest.digest()

    def __pad(self):
        # "\xff" is a dummy trailing byte, to increase the length of imput
        # data by one byte. Any byte could do. This is to account for the
        # trailing padding_length byte in the RFC
        self.padding = self.pkcs7.get_padding("%s%s\xff" % (self.crypto_data.data, self.mac))

    def __str__(self):
        return "%s%s%s%s%s" % (self.explicit_iv, self.crypto_data.data, self.mac, self.padding, self.padding_len)


class EAEADCryptoContainer(CryptoContainer):
    def __init__(self, crypto_data):
        super(EAEADCryptoContainer, self).__init__(crypto_data, None)
        self.aead = b""
        self.__aead()

    @classmethod
    def from_context(cls, tls_ctx, ctx, crypto_data):
        return cls(crypto_data)

    @classmethod
    def from_data(cls, tls_ctx, ctx, data):
        crypto_data = CryptoData.from_context(tls_ctx, ctx, data)
        return EAEADCryptoContainer.from_context(tls_ctx, ctx, crypto_data)

    def __aead(self):
        sequence_ = struct.pack("!Q", self.crypto_data.sequence)
        content_type_ = struct.pack("!B", self.crypto_data.content_type)
        version_ = struct.pack("!H", self.crypto_data.version)
        len_ = struct.pack("!H", self.crypto_data.data_len)
        self.aead = "%s%s%s%s" % (sequence_, content_type_, version_, len_)

    def __str__(self):
        return self.crypto_data.data


class IAEADCryptoContainer(CryptoContainer):
    def __init__(self, crypto_data):
        super(IAEADCryptoContainer, self).__init__(crypto_data, None)

    @classmethod
    def from_context(cls, tls_ctx, ctx, crypto_data):
        return cls(crypto_data)

    @classmethod
    def from_data(cls, tls_ctx, ctx, data):
        crypto_data = CryptoData.from_context(tls_ctx, ctx, data)
        return IAEADCryptoContainer.from_context(tls_ctx, ctx, crypto_data)

    def __str__(self):
        return b"%s%s%s" % (self.crypto_data.data, struct.pack("!B", self.crypto_data.content_type), self.crypto_data.padding)


class CryptoContainerFactory(object):
    crypto_container_map = {CipherMode.STREAM: StreamCryptoContainer,
                            CipherMode.CBC: CBCCryptoContainer,
                            CipherMode.EAEAD: EAEADCryptoContainer,
                            CipherMode.IAEAD: IAEADCryptoContainer}

    def __init__(self, tls_ctx):
        self.tls_ctx = tls_ctx
        self.sec_params = self.tls_ctx.sec_params
        self.cipher_mode = self.sec_params.cipher_mode_name

    def new(self, ctx, crypto_data):
        try:
            class_ = CryptoContainerFactory.crypto_container_map[self.cipher_mode]
        except KeyError:
            raise ValueError("Unavailable cipher mode: %s" % self.cipher_mode)
        return class_.from_context(self.tls_ctx, ctx, crypto_data)


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

    block_size = 0
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


class DH(object):
    pass


class DHE(DH):
    pass


class ECDHE(DH):
    pass


class ECDSA(object):
    pass


class TLSSecurityParameters(object):
    GCM_TAG_SIZE = 16
    GCM_EXPLICIT_IV_SIZE = 8

    crypto_params = {
        tls.TLSCipherSuite.NULL_WITH_NULL_NULL: {"name": tls.TLS_CIPHER_SUITES[0x0000], "export": False,
                                                 "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                 "cipher": {"type": NullCipher, "name": "NULL", "key_len": 0, "mode": None, "mode_name": CipherMode.STREAM},
                                                 "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.RSA_WITH_NULL_MD5: {"name": tls.TLS_CIPHER_SUITES[0x0001], "export": False,
                                               "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                               "cipher": {"type": NullCipher, "name": "NULL", "key_len": 0, "mode": None, "mode_name": CipherMode.STREAM},
                                               "hash": {"type": MD5, "name": "MD5"}},
        tls.TLSCipherSuite.RSA_WITH_NULL_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0002], "export": False,
                                               "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                               "cipher": {"type": NullCipher, "name": "NULL", "key_len": 0, "mode": None, "mode_name": CipherMode.STREAM},
                                               "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_EXPORT_WITH_RC4_40_MD5: {"name": tls.TLS_CIPHER_SUITES[0x0003], "export": True,
                                                        "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                        "cipher": {"type": ARC4, "name": "RC4", "key_len": 5, "mode": None, "mode_name": CipherMode.STREAM},
                                                        "hash": {"type": MD5, "name": "MD5"}},
        tls.TLSCipherSuite.RSA_WITH_RC4_128_MD5: {"name": tls.TLS_CIPHER_SUITES[0x0004], "export": False,
                                                  "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                  "cipher": {"type": ARC4, "name": "RC4", "key_len": 16, "mode": None, "mode_name": CipherMode.STREAM},
                                                  "hash": {"type": MD5, "name": "MD5"}},
        tls.TLSCipherSuite.RSA_WITH_RC4_128_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0005], "export": False,
                                                  "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                  "cipher": {"type": ARC4, "name": "RC4", "key_len": 16, "mode": None, "mode_name": CipherMode.STREAM},
                                                  "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_EXPORT_WITH_RC2_CBC_40_MD5: {"name": tls.TLS_CIPHER_SUITES[0x0006], "export": True,
                                                            "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                            "cipher": {"type": ARC2, "name": "RC2", "key_len": 5, "mode": ARC2.MODE_CBC, "mode_name": CipherMode.CBC},
                                                            "hash": {"type": MD5, "name": "MD5"}},
        # 0x0007: RSA_WITH_IDEA_CBC_SHA => IDEA support would require python openssl bindings
        tls.TLSCipherSuite.RSA_EXPORT_WITH_DES40_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0008], "export": True,
                                                           "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                           "cipher": {"type": DES, "name": "DES", "key_len": 5, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                           "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_WITH_DES_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0009], "export": False,
                                                  "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                  "cipher": {"type": DES, "name": "DES", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                  "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_WITH_3DES_EDE_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x000a], "export": False,
                                                       "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                       "cipher": {"type": DES3, "name": "DES3", "key_len": 24, "mode": DES3.MODE_CBC, "mode_name": CipherMode.CBC},
                                                       "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x002f], "export": False,
                                                      "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                      "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0035], "export": False,
                                                      "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                      "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_WITH_NULL_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x003b], "export": False,
                                                  "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                  "cipher": {"type": NullCipher, "name": "NULL", "key_len": 0, "mode": None, "mode_name": CipherMode.STREAM},
                                                  "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x003c], "export": False,
                                                      "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                      "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x003d], "export": False,
                                                      "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                      "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC4_56_MD5: {"name": tls.TLS_CIPHER_SUITES[0x0060], "export": True,
                                                            "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                            "cipher": {"type": ARC4, "name": "RC4", "key_len": 8, "mode": None, "mode_name": CipherMode.STREAM},
                                                            "hash": {"type": MD5, "name": "MD5"}},
        tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC2_CBC_56_MD5: {"name": tls.TLS_CIPHER_SUITES[0x0061], "export": True,
                                                                "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                                "cipher": {"type": ARC2, "name": "RC2", "key_len": 8, "mode": ARC2.MODE_CBC, "mode_name": CipherMode.CBC},
                                                                "hash": {"type": MD5, "name": "MD5"}},
        tls.TLSCipherSuite.RSA_EXPORT1024_WITH_DES_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0062], "export": True,
                                                             "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                             "cipher": {"type": DES, "name": "DES", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                             "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC4_56_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0064], "export": True,
                                                            "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": None},
                                                            "cipher": {"type": ARC4, "name": "RC4", "key_len": 8, "mode": None, "mode_name": CipherMode.STREAM},
                                                            "hash": {"type": SHA, "name": "SHA"}},
        # 0x0084: RSA_WITH_CAMELLIA_256_CBC_SHA => Camelia support should use camcrypt or the camelia patch for pycrypto
        tls.TLSCipherSuite.DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0011], "export": True,
                                                               "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                               "cipher": {"type": DES, "name": "DES", "key_len": 5, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                               "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_DES_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0012], "export": False,
                                                      "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                      "cipher": {"type": DES, "name": "DES", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                      "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_3DES_EDE_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0013], "export": False,
                                                           "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                           "cipher": {"type": DES3, "name": "DES3", "key_len": 24, "mode": DES3.MODE_CBC, "mode_name": CipherMode.CBC},
                                                           "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0014], "export": True,
                                                               "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                               "cipher": {"type": DES, "name": "DES", "key_len": 5, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                               "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_DES_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0015], "export": False,
                                                      "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                      "cipher": {"type": DES, "name": "DES", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                      "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_3DES_EDE_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0016], "export": False,
                                                           "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                           "cipher": {"type": DES3, "name": "DES3", "key_len": 24, "mode": DES3.MODE_CBC, "mode_name": CipherMode.CBC},
                                                           "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0032], "export": False,
                                                          "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                          "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                          "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0033], "export": False,
                                                          "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                          "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                          "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_AES_256_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0038], "export": False,
                                                          "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                          "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                          "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0039], "export": False,
                                                          "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                          "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                          "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0063], "export": True,
                                                                 "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                                 "cipher": {"type": DES, "name": "DES", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                                 "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_EXPORT1024_WITH_RC4_56_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0065], "export": True,
                                                                "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                                "cipher": {"type": ARC4, "name": "RC4", "key_len": 8, "mode": None, "mode_name": CipherMode.STREAM},
                                                                "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_RC4_128_SHA: {"name": tls.TLS_CIPHER_SUITES[0x0066], "export": False,
                                                      "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                      "cipher": {"type": ARC4, "name": "RC4", "key_len": 16, "mode": None, "mode_name": CipherMode.STREAM},
                                                      "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x0067], "export": False,
                                                          "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                          "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                          "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_256_CBC_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x006b], "export": False,
                                                          "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                          "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                          "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_NULL_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc006], "export": False,
                                                       "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                       "cipher": {"type": NullCipher, "name": "NULL", "key_len": 0, "mode": None, "mode_name": CipherMode.STREAM},
                                                       "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_RC4_128_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc007], "export": False,
                                                          "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                          "cipher": {"type": ARC4, "name": "RC4", "key_len": 16, "mode": None, "mode_name": CipherMode.STREAM},
                                                          "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc008], "export": False,
                                                               "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                               "cipher": {"type": DES3, "name": "DES3", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                               "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc009], "export": False,
                                                              "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                              "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                              "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_256_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc00a], "export": False,
                                                              "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                              "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                              "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_NULL_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc010], "export": False,
                                                     "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                     "cipher": {"type": NullCipher, "name": "NULL", "key_len": 0, "mode": None, "mode_name": CipherMode.STREAM},
                                                     "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_RC4_128_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc011], "export": False,
                                                        "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                        "cipher": {"type": ARC4, "name": "RC4", "key_len": 16, "mode": None, "mode_name": CipherMode.STREAM},
                                                        "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc012], "export": False,
                                                             "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                             "cipher": {"type": DES3, "name": "DES3", "key_len": 8, "mode": DES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                             "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc013], "export": False,
                                                            "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                            "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                            "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA: {"name": tls.TLS_CIPHER_SUITES[0xc014], "export": False,
                                                            "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                            "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                            "hash": {"type": SHA, "name": "SHA"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: {"name": tls.TLS_CIPHER_SUITES[0xc023], "export": False,
                                                                 "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                                 "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                                 "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: {"name": tls.TLS_CIPHER_SUITES[0xc024], "export": False,
                                                                 "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                                 "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                                 "hash": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256: {"name": tls.TLS_CIPHER_SUITES[0xc027], "export": False,
                                                               "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                               "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                               "hash": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA384: {"name": tls.TLS_CIPHER_SUITES[0xc028], "export": False,
                                                               "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                               "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CBC, "mode_name": CipherMode.CBC},
                                                               "hash": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.RSA_WITH_AES_128_GCM_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x009c], "export": False,
                                                                 "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": RSA},
                                                                 "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                                 "hash": {"type": NullHash, "name": "NULL"},
                                                                 "prf": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.RSA_WITH_AES_256_GCM_SHA384: {"name": tls.TLS_CIPHER_SUITES[0x009d], "export": False,
                                                         "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": RSA},
                                                         "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                         "hash": {"type": NullHash, "name": "NULL"},
                                                         "prf": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_128_GCM_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x009e], "export": False,
                                                         "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                         "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                         "hash": {"type": NullHash, "name": "NULL"},
                                                         "prf": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_256_GCM_SHA384: {"name": tls.TLS_CIPHER_SUITES[0x009f], "export": False,
                                                             "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                             "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                             "hash": {"type": NullHash, "name": "NULL"},
                                                             "prf": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_AES_128_GCM_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x00a2], "export": False,
                                                             "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": DSA},
                                                             "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                             "hash": {"type": NullHash, "name": "NULL"},
                                                             "prf": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.DHE_DSS_WITH_AES_256_GCM_SHA384: {"name": tls.TLS_CIPHER_SUITES[0x009e], "export": False,
                                                             "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                             "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                             "hash": {"type": NullHash, "name": "NULL"},
                                                             "prf": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {"name": tls.TLS_CIPHER_SUITES[0xc02b], "export": False,
                                                               "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                               "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                               "hash": {"type": NullHash, "name": "NULL"},
                                                               "prf": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {"name": tls.TLS_CIPHER_SUITES[0xc02c], "export": False,
                                                                 "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                                 "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                                 "hash": {"type": NullHash, "name": "NULL"},
                                                                 "prf": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256: {"name": tls.TLS_CIPHER_SUITES[0xc02f], "export": False,
                                                               "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                               "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                               "hash": {"type": NullHash, "name": "NULL"},
                                                               "prf": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_256_GCM_SHA384: {"name": tls.TLS_CIPHER_SUITES[0xc030], "export": False,
                                                               "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": RSA},
                                                               "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_GCM, "mode_name": CipherMode.EAEAD},
                                                               "hash": {"type": NullHash, "name": "NULL"},
                                                               "prf": {"type": SHA384, "name": "SHA384"}},
        tls.TLSCipherSuite.RSA_WITH_AES_128_CCM: {"name": tls.TLS_CIPHER_SUITES[0xc09c], "export": False,
                                                  "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": RSA},
                                                  "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CCM, "mode_name": CipherMode.EAEAD},
                                                  "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.RSA_WITH_AES_256_CCM: {"name": tls.TLS_CIPHER_SUITES[0xc09d], "export": False,
                                                  "key_exchange": {"type": RSA, "name": tls.TLSKexNames.RSA, "sig": RSA},
                                                  "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CCM, "mode_name": CipherMode.EAEAD},
                                                  "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_128_CCM: {"name": tls.TLS_CIPHER_SUITES[0xc09e], "export": False,
                                                      "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CCM, "mode_name": CipherMode.EAEAD},
                                                      "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.DHE_RSA_WITH_AES_256_CCM: {"name": tls.TLS_CIPHER_SUITES[0xc09f], "export": False,
                                                      "key_exchange": {"type": DHE, "name": tls.TLSKexNames.DHE, "sig": RSA},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CCM, "mode_name": CipherMode.EAEAD},
                                                      "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_128_CCM: {"name": tls.TLS_CIPHER_SUITES[0xc0ac], "export": False,
                                                      "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_CCM, "mode_name": CipherMode.EAEAD},
                                                      "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.ECDHE_ECDSA_WITH_AES_256_CCM: {"name": tls.TLS_CIPHER_SUITES[0xc0ad], "export": False,
                                                      "key_exchange": {"type": ECDHE, "name": tls.TLSKexNames.ECDHE, "sig": ECDSA},
                                                      "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_CCM, "mode_name": CipherMode.EAEAD},
                                                      "hash": {"type": NullHash, "name": "NULL"}},
        tls.TLSCipherSuite.TLS_AES_128_GCM_SHA256: {"name": tls.TLS_CIPHER_SUITES[0x1301], "export": False,
                                                    "cipher": {"type": AES, "name": "AES", "key_len": 16, "mode": AES.MODE_GCM, "mode_name": CipherMode.IAEAD,
                                                               "iv_len": 12},
                                                    "prf": {"type": SHA256, "name": "SHA256"}},
        tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384: {"name": tls.TLS_CIPHER_SUITES[0x1302], "export": False,
                                                    "cipher": {"type": AES, "name": "AES", "key_len": 32, "mode": AES.MODE_GCM, "mode_name": CipherMode.IAEAD,
                                                               "iv_len": 12},
                                                    "prf": {"type": SHA384, "name": "SHA384"}},
        # 0x0087: DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => Camelia support should use camcrypt or the camelia patch for pycrypto
        # 0x0088: DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => Camelia support should use camcrypt or the camelia patch for pycrypto
    }
# Unsupported for now, until CCM and SRP are integrated
#         SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xc021
#         SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xc022
#         TLS_FALLBACK_SCSV = 0x5600
# No support for 8 byte tags
#     0xc0ac: "ECDHE_ECDSA_WITH_AES_128_CCM",
#     0xc0ad: "ECDHE_ECDSA_WITH_AES_256_CCM",
#     0xc0ae: "ECDHE_ECDSA_WITH_AES_128_CCM_8",
#     0xc0af: "ECDHE_ECDSA_WITH_AES_256_CCM_8",
#     0xc0a0: 'RSA_WITH_AES_128_CCM_8',
#     0xc0a1: 'RSA_WITH_AES_256_CCM_8',
#     0xc0a2: 'DHE_RSA_WITH_AES_128_CCM_8',
#     0xc0a3: 'DHE_RSA_WITH_AES_256_CCM_8',
#     0xc0ac: 'ECDHE_ECDSA_WITH_AES_128_CCM',
#     0xc0ad: 'ECDHE_ECDSA_WITH_AES_256_CCM',
#     0xc0ae: 'ECDHE_ECDSA_WITH_AES_128_CCM_8',
#     0xc0af: 'ECDHE_ECDSA_WITH_AES_256_CCM_8',

    def __init__(self, prf, cipher_suite, client_random, server_random):
        try:
            self.negotiated_crypto_param = self.crypto_params[cipher_suite]
        except KeyError:
            raise RuntimeError("Cipher 0x%04x not supported" % cipher_suite)
        else:
            if len(client_random) != 32:
                raise ValueError("Client random must be 32 bytes")
            self.client_random = client_random
            if len(server_random) != 32:
                raise ValueError("Server random must be 32 bytes")
            self.server_random = server_random
            self.block_size = self.negotiated_crypto_param["cipher"]["type"].block_size
            self.cipher_mode = self.negotiated_crypto_param["cipher"]["mode"]
            self.cipher_mode_name = self.negotiated_crypto_param["cipher"]["mode_name"]
            self.cipher_type = self.negotiated_crypto_param["cipher"]["type"]
            self.hash_type = self.negotiated_crypto_param.get("hash", {}).get("type", NullHash)
            self.prf = prf
            self.pms = b""
            self.master_secret = b""
            self.client_keystore, self.server_keystore = [tlsk.EmptySymKeyStore()] * 2
            self.__set_sec_param_sizes()

    def __set_sec_param_sizes(self):
        # Stream ciphers have a block size of one, but IV should be 0
        if self.cipher_mode_name == CipherMode.EAEAD:
            self.mac_key_length = 0
            self.iv_length = 4
        elif self.cipher_mode_name == CipherMode.IAEAD:
            self.mac_key_length = 0
            self.iv_length = 12
        elif self.cipher_mode_name == CipherMode.CBC:
            self.mac_key_length = self.negotiated_crypto_param["hash"]["type"].digest_size
            self.iv_length = self.block_size
        elif self.cipher_mode_name == CipherMode.STREAM:
            self.mac_key_length = self.negotiated_crypto_param["hash"]["type"].digest_size
            self.iv_length = 0
        else:
            raise ValueError("Unknown cipher mode")
        self.cipher_key_length = self.negotiated_crypto_param["cipher"]["key_len"]

    @classmethod
    def from_pre_master_secret(cls, prf, cipher_suite, pms, client_random, server_random):
        sec_params = cls(prf, cipher_suite, client_random, server_random)
        sec_params.pms = pms
        sec_params.generate_master_secret(pms, client_random, server_random)
        sec_params.client_keystore, sec_params.server_keystore = sec_params.init_keys(client_random, server_random)
        return sec_params

    @classmethod
    def from_master_secret(cls, prf, cipher_suite, master_secret, client_random, server_random):
        sec_params = cls(prf, cipher_suite, client_random, server_random)
        sec_params.master_secret = master_secret
        sec_params.client_keystore, sec_params.server_keystore = sec_params.init_keys(client_random, server_random)
        return sec_params

    def __init_key_material(self, data):
        i = 0
        client_mac_key = data[i:i + self.mac_key_length]
        i += self.mac_key_length
        server_mac_key = data[i:i + self.mac_key_length]
        i += self.mac_key_length
        client_key = data[i:i + self.cipher_key_length]
        i += self.cipher_key_length
        server_key = data[i:i + self.cipher_key_length]
        i += self.cipher_key_length
        client_iv = data[i:i + self.iv_length]
        i += self.iv_length
        server_iv = data[i:i + self.iv_length]
        i += self.iv_length
        client_keystore = tlsk.CipherKeyStore(self.negotiated_crypto_param, client_key, client_mac_key,
                                              client_iv)
        server_keystore = tlsk.CipherKeyStore(self.negotiated_crypto_param, server_key, server_mac_key,
                                              server_iv)
        return client_keystore, server_keystore

    def generate_master_secret(self, pms, client_random, server_random):
        self.master_secret = self.prf.get_bytes(pms, TLSPRF.TLS_MD_MASTER_SECRET_CONST,
                                                client_random + server_random, num_bytes=48)
        return self.master_secret

    def init_keys(self, client_random, server_random, master_secret=None):
        if master_secret is None:
            master_secret = self.master_secret
        key_block = self.prf.get_bytes(master_secret, TLSPRF.TLS_MD_KEY_EXPANSION_CONST, server_random + client_random,
                                       num_bytes=2 * (self.mac_key_length + self.cipher_key_length + self.iv_length))
        return self.__init_key_material(key_block)

    def __str__(self):
        s = []
        for f in (f for f in dir(self) if "_write_" in f):
            s.append("%20s | %s" % (f, repr(getattr(self, f))))
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

    comp_params = {tls.TLSCompressionMethod.NULL: {"name": tls.TLS_COMPRESSION_METHODS[0x00], "type": NullCompression},
                   tls.TLSCompressionMethod.DEFLATE: {"name": tls.TLS_COMPRESSION_METHODS[0x01], "type": zlib}}
