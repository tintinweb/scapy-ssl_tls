#! -*- coding: utf-8 -*-

import os
import binascii
import unittest
import struct
import warnings

import tinyec.ec as ec
import tinyec.registry as reg
import scapy_ssl_tls.ssl_tls as tls
import scapy_ssl_tls.ssl_tls_crypto as tlsc
import scapy_ssl_tls.ssl_tls_keystore as tlsk

from Cryptodome.Hash import HMAC, MD5, SHA, SHA256, SHA384
from Cryptodome.Cipher import AES, DES3, PKCS1_v1_5
from Cryptodome.PublicKey import RSA


def env_local_file(file):
    return os.path.join(os.path.dirname(__file__), "files", file)


class TestNullCiper(unittest.TestCase):

    def test_null_cipher_returns_cleartext_on_encrypt(self):
        null_cipher = tlsc.NullCipher.new(key="junk_key", iv="junk_iv")
        cleartext = "cleartext"
        self.assertEqual(cleartext, null_cipher.encrypt(cleartext))

    def test_null_cipher_returns_ciphertext_on_decrypt(self):
        null_cipher = tlsc.NullCipher.new(key="junk_key", iv="junk_iv")
        cleartext = "cleartext"
        ciphertext = null_cipher.encrypt(cleartext)
        self.assertEqual(ciphertext, null_cipher.decrypt(ciphertext))


class TestNullHash(unittest.TestCase):

    def test_null_hash_always_returns_empty_string(self):
        null_hash = tlsc.NullHash.new("initial_junk")
        null_hash.update("some more junk")
        self.assertEqual("", null_hash.digest())
        self.assertEqual("", null_hash.hexdigest())

    def test_null_hash_with_pycrypto_hmac(self):
        hmac = HMAC.new("secret", "stuff", digestmod=tlsc.NullHash)
        hmac.update("some more stuff")
        self.assertEqual("", hmac.digest())
        self.assertEqual("", hmac.hexdigest())


class TestTLSSessionCtx(unittest.TestCase):

    def setUp(self):
        self.pem_priv_key = """-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDDLrmt4lKRpm6P
2blptwJsa1EBuxuuAayLjwNqKGvm5c1CAUEa/NtEpUMM8WYKRDwxzakUIGI/BdP3
NOEMphcs5+OekgJLhzoSdtAIrXPy8JIidENZE6FzCJ2b6fHU5O4hoNvv1Bx5yoZr
HVaWJIZMRRocJJ0Nf9oMaU8IE6m6OdBzQHEwcnL2/a8Q3VxstHufzjILmaZD9WL+
6AESlQMKZPNQ+Xd7d4nvnVkY4ZV46tA+KvADGuotgovQwG+uiyQoGRrQUms21vHF
zIvd3G9OCiyCTCHSyfsE3g7tks33NZ8O8gF8xa9OmU9TQPwwAyUr6JQXz0CW77o7
Cr9LpHuNAgMBAAECggEBAJRbMbtfqc8XqDYjEfGur2Lld19Pb0yl7RbvD3NjYhDR
X2DqPyhaRfg5fWubGSp4jyBz6C5qJwMsVN80DFNm83qoj7T52lC6aoOaV6og3V8t
SIZzxLUyXKdpRxM5kR13HSHmeQYkPbi9HcrRM/1PqdzTMXNuyQl3wq9oZDAJchsf
fmoh080htkaxhEb1bMXa2Lj7j2OIkHOsQeIu6BdbxIKRPIT+zrcklE6ocW8fTWAS
Qi3IZ1FYLL+fs6TTxjx0VkC8QLaxWxY0pqTiwS7ndZiZKc3l3ARuvRk8buP+X3Jg
BD86FQ18OXZC9boMbDbzv2cOLtdkq5pS3lJE4F9gjYECgYEA69ukU2pNWot2OPwK
PuPwAXWNrvnvFzQgIc0qOiCmgKJU6wqunlop4Bx5XmetHExVyJVBEhaHoDr0F3Rs
gt8IclKDsWGXoVcgfu3llMimiZ05hOf/XtcGTCZwZenMQ30cFh4ZRuUu7WCZ9tqO
28P8jCXB3IcaRpRnNvVvmCr5NXECgYEA09nUzRW993SlohceRW2C9fT9HZ4BaPWO
5wVlnoo5mlUfAyzl+AGT/WlKmrn/1gAHIznQJ8ZIABQvPaBXhvkANXZP5Ie0lObw
jA7qFuKt7yV4GGlDnU1MOLh+acABMQBGSx8BJDaomH7glTiPEPTZjoP6wfAsd1uv
Knjt7jH2ad0CgYEAx9ghknRd+rx0fbBBVix4riPW20324ihOmZVnlD0aF6B0Z3tz
ncUz+irmQ7GBIpsjjIO60QK6BHAvZrhFQVaNp6B26ZORkSlr5WDZyImDYtMPa6fP
36I+OcPQNOo3I3Acnjj+ne2PJ59Ula92oIudr3pGmv72qpsQIacw2TSAWGECgYEA
sdNAN+HPMn68ZaGoLDjvW8uIB6tQnay5hhvWn8yA65YV0RGH+7Q/Z9BQ6i3EnPor
A5uMqUZbu4011jHYJpiuXzHvf/GVWAO92KLQReOCgqHd/Aen1MtEdrwOiG+90Ebd
ukLNL3ud61tc4oS2OlJ8p48LFm2mtY3FLA6UEYPoxhUCgYEAtsfWIGnBh7XC+HwI
2higSgN92VpJHSPOyOi0aG/u5AEQ+fsCUIi3KakxzvmiGMAEvWItkKyz2Gu8smtn
2HVsGxI5UW7aLw9s3qe8kyMSfUk6pGamVhJUQmDr77+5zEzykPBxwGwDwdeR43CR
xVgf/Neb/avXgIgi6drj8dp1fWA=
-----END PRIVATE KEY-----
        """
        rsa_priv_key = RSA.importKey(self.pem_priv_key)
        self.priv_key = PKCS1_v1_5.new(rsa_priv_key)
        self.pub_key = PKCS1_v1_5.new(rsa_priv_key.publickey())
        self.tls13_client_extensions = [tls.TLSExtension() / tls.TLSExtSupportedVersions(),
                                        tls.TLSExtension() / tls.TLSExtSignatureAlgorithms(),
                                        tls.TLSExtension() / tls.TLSExtSupportedGroups(),
                                        tls.TLSExtension() / tls.TLSExtALPN(),
                                        tls.TLSExtension() / tls.TLSExtECPointsFormat(),
                                        tls.TLSExtension() / tls.TLSExtServerNameIndication(server_names=tls.TLSServerName(data="sni.example.com")),
                                        tls.TLSExtension(type=tls.TLSExtensionType.EXTENDED_MASTER_SECRET)]
        self.tls13_server_extensions = []
        unittest.TestCase.setUp(self)

    def test_negotiated_cipher_is_used_in_context(self):
        # RSA_WITH_NULL_MD5
        cipher_suite = 0x1
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(gmt_unix_time=123456, random_bytes="A" * 28,
                                                                                                      cipher_suite=cipher_suite)])
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.negotiated.key_exchange,
                         tlsc.TLSSecurityParameters.crypto_params[cipher_suite]["key_exchange"]["name"])
        self.assertEqual(tls_ctx.negotiated.mac,
                         tlsc.TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["name"])

    def test_negotiated_compression_method_is_used_in_context(self):
        # DEFLATE
        compression_method = 0x1
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(gmt_unix_time=123456, random_bytes="A" * 28,
                                                                                                      compression_method=compression_method)])
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.negotiated.compression_algo,
                         tlsc.TLSCompressionParameters.comp_params[compression_method]["name"])
        input_ = "some data" * 16
        self.assertEqual(tls_ctx.client_ctx.compression.decompress(tls_ctx.client_ctx.compression.compress(input_)),
                         input_)

    def test_encrypted_pms_is_only_available_after_server_certificate_is_presented(self):
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello()])
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        with self.assertRaises(ValueError):
            tls_ctx.get_encrypted_pms()

    def test_encrypting_pms_fails_if_no_certificate_in_connection(self):
        tls_ctx = tlsc.TLSSessionCtx()
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(version=0x0301)])
        tls_ctx.insert(pkt)
        with self.assertRaises(ValueError):
            tls_ctx.get_encrypted_pms()

    def test_random_pms_is_generated_on_client_hello(self):
        tls_ctx = tlsc.TLSSessionCtx()
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(version=0x0301)])
        tls_ctx.insert(pkt)
        self.assertIsNotNone(tls_ctx.premaster_secret)

    def test_keys_are_set_in_context_when_loaded(self):
        tls_ctx = tlsc.TLSSessionCtx()
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(version=0x0301)])
        tls_ctx.insert(pkt)
        tls_ctx.server_ctx.load_rsa_keys(self.pem_priv_key)
        self.assertIsNotNone(tls_ctx.server_ctx.asym_keystore.private)
        self.assertIsNotNone(tls_ctx.server_ctx.asym_keystore.public)
        # Broken due to pycrypto bug: https://github.com/dlitz/pycrypto/issues/114
        # Uncomment when fixed upstream
        # self.assertTrue(tls_ctx.crypto.server.asym_keystore.private.can_decrypt())
        # self.assertTrue(tls_ctx.crypto.server.asym_keystore.public.can_decrypt())
        self.assertTrue(tls_ctx.server_ctx.asym_keystore.private.can_encrypt())
        # TODO: Invertigate further: broken also in pycrypto. Should return False for public keys.
        # self.assertFalse(tls_ctx.crypto.server.asym_keystore.public.can_encrypt())

    def test_decrypted_pms_matches_generated_pms(self):
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.server_ctx.load_rsa_keys(self.pem_priv_key)
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello()])
        tls_ctx.insert(pkt)
        epms = tls_ctx.get_encrypted_pms()
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello()])
        tls_ctx.insert(pkt)
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() / tls.TLSClientRSAParams(data=epms)])
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.encrypted_premaster_secret, epms)
        self.assertEqual(tls_ctx.premaster_secret, self.priv_key.decrypt(epms, None))

    def test_fixed_crypto_data_matches_verify_data(self):
        version = tls.TLSVersion.TLS_1_0
        client_verify_data = "e23f73911909a86be9e93fdb"
        server_verify_data = "dfed5860b3eb4a3deaa9cf39"
        tls_ctx = tlsc.TLSSessionCtx()
        # tls_ctx.rsa_load_keys(self.pem_priv_key)
        client_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(version=version,
                                                                                                               gmt_unix_time=1234,
                                                                                                               random_bytes="A" * 28)])
        # Hello Request should be ignored in verify_data calculation
        tls_ctx.insert(tls.TLSHelloRequest())
        tls_ctx.insert(client_hello)
        tls_ctx.premaster_secret = "B" * 48
        epms = "C" * 256
        server_hello = tls.TLSRecord(version=version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(version=version,
                                                                                                                              gmt_unix_time=1234,
                                                                                                                              session_id="",
                                                                                                                              random_bytes="A" * 28)])
        tls_ctx.insert(server_hello)
        client_kex = tls.TLSRecord(version=version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() /
            tls.TLSClientRSAParams(data=epms)])
        tls_ctx.insert(client_kex)
        self.assertEqual(client_verify_data, binascii.hexlify(tls_ctx.get_verify_data()))
        # Make sure that client finish is included in server finish calculation
        tls_ctx.set_mode(server=True)
        verify_data = tls_ctx.get_verify_data()
        client_finish = tls.TLSRecord(version=version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSFinished(data=verify_data)])
        tls_ctx.insert(client_finish)
        self.assertEqual(server_verify_data, binascii.hexlify(verify_data))

    def test_client_dh_parameters_generation_matches_fixed_data(self):
        tls_ctx = tlsc.TLSSessionCtx()
        p = 11435638110073884015312138951374632602058080675070521707579703088370446597672067452229024566834732449017970455481029703480957707976441965258194321262569523
        g = 2
        public = 5138256925703068273978027748090991496798559132548080008963338818789329120888330364361710579103845963013102056863555649866832856399945018230203391434938503
        tls_ctx.server_ctx.kex_keystore = tlsk.DHKeyStore(g, p, public)
        client_privkey = 5398526532442504864680398257365369432058147704829279760748758494328728516319
        client_pubkey = tls_ctx.get_client_dh_pubkey(client_privkey)
        self.assertEqual(
            ("/T\xdc;\xc49\xa6\x8cD\xd4\xc1\x07I|\xb6\xc8\xaf\xb5\x04\xe9\xfb\t\x0e}\x14~\xa4\x1f\xdfo\x08u)Z\xb3\x0e"
             "\x1c^\xa3x0\x90\xa1\xd7\x82\x9dLT\xa6^\xcc\xf7\xae\x87\x97\x86vi\x02s\x10\xb3\xdbo"),
            client_pubkey)
        self.assertEqual(
            ("}\xcae\xd2y\xd7F$\xde\"\xa9s\xfbNR9v\x19t9\x87\xa8\xa3\x9c\xccb]\x13\xb7\x8a\x8f\xdf\x7fv\x05\xa6\xf1\xa7"
             "\xc8\xf4X\xe3\xd4\xac\xd6\x1e4\xb4\x1cc\xbb\xce\xbe\x94lQ\x91\xb9\xde\xb7\xa6gu_"),
            tlsk.int_to_str(tls_ctx.client_ctx.kex_keystore.get_psk(tls_ctx.server_ctx.kex_keystore.public)))

    def test_client_ecdh_parameters_generation_matches_fixed_data(self):
        tls_ctx = tlsc.TLSSessionCtx()
        secp256r1 = reg.get_curve("secp256r1")
        public = ec.Point(secp256r1, 71312736565121892539464098105317518227531978702333415386264829982789952731614,
                          108064706642599821618918248475955325719985341096102200103424860263181813987462)
        tls_ctx.server_ctx.kex_keystore = tlsk.ECDHKeyStore(secp256r1, public)
        client_privkey = 15320484772785058360598040144348894600917526501829289880527760633524785596585
        client_keys = ec.Keypair(secp256r1, client_privkey)
        client_pubkey = tls_ctx.get_client_ecdh_pubkey(client_privkey)
        self.assertTrue(client_pubkey.startswith("\x04"))
        self.assertEqual("\x04%s%s" % (tlsk.int_to_str(client_keys.pub.x), tlsk.int_to_str(client_keys.pub.y)),
                         client_pubkey)
        self.assertEqual(client_keys.pub, tls_ctx.client_ctx.kex_keystore.public)
        self.assertEqual("'(\x17\x94l\xd7AO\x03\xd4Fi\x05}mP\x1aX5C7\xf0_\xa9\xb0\xac\xba{r\x1f\x12\x8f",
                         tls_ctx.premaster_secret)

    def test_after_tl13_server_hello_then_key_material_is_installed(self):
        tls_ctx = tlsc.TLSSessionCtx()
        nist256 = reg.get_curve(tls.TLS_SUPPORTED_GROUPS[tls.TLSSupportedGroup.SECP256R1])
        keypair = ec.make_keypair(nist256)
        client_keystore = tlsk.ECDHKeyStore.from_keypair(nist256, keypair)
        tls_ctx.client_ctx.shares.append(client_keystore)
        ec_pub = tlsk.point_to_ansi_str(keypair.pub)
        key_share = tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSClientHelloKeyShare(
            client_shares=[tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP256R1, key_exchange=ec_pub)])
        self.tls13_client_extensions.append(key_share)
        client_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
                                                                       tls.TLSClientHello(cipher_suites=[tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384],
                                                                                          extensions=self.tls13_client_extensions)])
        self.assertEqual(len(tls_ctx.client_ctx.shares), 1)
        self.assertIn(client_keystore, tls_ctx.client_ctx.shares)
        self.assertIsNotNone(tls_ctx.client_ctx.shares[0].private)
        tls_ctx.insert(client_hello)
        self.assertIsNotNone(tls_ctx.client_ctx.shares[0].private)
        self.assertEqual(client_keystore, tls_ctx.client_ctx.shares[0])

        server_ec_pub = ("\x043\xc0\xd0D\xa6\xe8\x9c\xbf\xf7\x0e\xa1\x80\xdf\x15\n\xf3\x85\x7f\xf6\xb2\xa2\x01\xfc\xcf\x93FH"
                         "\xed\xfa\x87\xb0\x19L\xc5\xb1\xd6\xf0\xcap?\xf1\xe7\x04\xc5\xde\xba/\xea\x1a\x86\xfb\xc9\rI\x9cU?r`"
                         "\x18\xac\xb95\xc8")
        tls13_server_extensions = [tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSServerHelloKeyShare(
            server_share=tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP256R1, key_exchange=server_ec_pub))]
        server_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
                                                                       tls.TLSServerHello(version=tls.TLSVersion.TLS_1_3,
                                                                                          cipher_suite=tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                                                                                          extensions=tls13_server_extensions)])
        tls_ctx.insert(server_hello)
        self.assertNotIsInstance(tls_ctx.client_ctx.kex_keystore, tlsk.EmptyKexKeystore)
        self.assertNotIsInstance(tls_ctx.server_ctx.kex_keystore, tlsk.EmptyKexKeystore)
        self.assertIsNotNone(tls_ctx.group_secret)
        self.assertIsNone(tls_ctx.premaster_secret)
        self.assertIsNone(tls_ctx.master_secret)
        self.assertNotIsInstance(tls_ctx.client_ctx.sym_keystore, tlsk.EmptySymKeyStore)
        self.assertNotIsInstance(tls_ctx.server_ctx.sym_keystore, tlsk.EmptySymKeyStore)
        self.assertEqual(len(tls_ctx.client_ctx.sym_keystore_history), 1)
        self.assertEqual(len(tls_ctx.server_ctx.sym_keystore_history), 1)

    def test_when_mismatching_key_shares_are_used_then_a_protocol_error_is_raised(self):
        tls_ctx = tlsc.TLSSessionCtx()
        client_key_share = tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSClientHelloKeyShare(
            client_shares=[tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP256R1, key_exchange="\x041234")])
        client_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
                                                                       tls.TLSClientHello(cipher_suites=[tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384],
                                                                                          extensions=[client_key_share,
                                                                                                      tls.TLSExtension() / tls.TLSExtSupportedVersions()])])
        server_key_share = tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSServerHelloKeyShare(
            server_share=tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP521R1, key_exchange="\x041234"))
        server_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
                                                                       tls.TLSServerHello(version=tls.TLSVersion.TLS_1_3,
                                                                                          cipher_suite=tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                                                                                          extensions=[server_key_share])])
        # Ignore off curve warnings generated by the invalid keys
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tls_ctx.insert(client_hello)
            with self.assertRaises(tls.TLSProtocolError):
                tls_ctx.insert(server_hello)
        self.assertIsInstance(tls_ctx.client_ctx.kex_keystore, tlsk.EmptyKexKeystore)
        self.assertNotIsInstance(tls_ctx.server_ctx.kex_keystore, tlsk.EmptyKexKeystore)
        self.assertIsNone(tls_ctx.master_secret)


class TestTLSSecurityParameters(unittest.TestCase):

    def setUp(self):
        self.prf = tlsc.TLSPRF(tls.TLSVersion.TLS_1_0)
        self.pre_master_secret = "\x03\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
        self.client_random = "a" * 32
        self.server_random = "z" * 32
        self.master_secret = binascii.unhexlify(
            "43278712b1feba3622c5745f79908a77b6e801239fc19390240cc45a17517b6218dfcb3f370c97f15329251e7a20ffb0")
        unittest.TestCase.setUp(self)

    def test_unsupported_cipher_suite_throws_exception(self):
        with self.assertRaises(RuntimeError):
            tlsc.TLSSecurityParameters(self.prf, 0xffff, self.client_random, self.server_random)

    def test_building_with_supported_cipher_sets_lengths(self):
        # RSA_WITH_AES_128_CBC_SHA
        cipher_suite = 0x2f
        sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        self.assertEqual(sec_params.cipher_key_length, 16)
        self.assertEqual(sec_params.mac_key_length, SHA.digest_size)
        self.assertEqual(sec_params.iv_length, AES.block_size)

    def test_building_with_null_cipher_sets_lengths(self):
        # RSA_WITH_NULL_MD5
        cipher_suite = 0x1
        sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        self.assertEqual(sec_params.cipher_key_length, 0)
        self.assertEqual(sec_params.mac_key_length, MD5.digest_size)
        self.assertEqual(sec_params.iv_length, tlsc.NullCipher.block_size)

    def test_cleartext_message_matches_decrypted_message_with_block_cipher(self):
        # RSA_WITH_AES_128_CBC_SHA
        cipher_suite = 0x2f
        plaintext = "a" * 32
        sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        self.assertEqual(sec_params.master_secret, self.master_secret)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.version = tls.TLSVersion.TLS_1_1
        tls_ctx.requires_iv = True
        tls_ctx.sec_params = sec_params
        tls_ctx.client_ctx.sym_keystore = sec_params.client_keystore
        tls_ctx.server_ctx.sym_keystore = sec_params.server_keystore
        self.assertEqual(sec_params.master_secret, self.master_secret)
        crypto_ctx = tlsc.CBCCryptoContext(tls_ctx, tls_ctx.client_ctx)
        tls_ctx.client_ctx.crypto_ctx = crypto_ctx
        crypto_container = tlsc.CBCCryptoContainer.from_data(tls_ctx, tls_ctx.client_ctx, plaintext)
        decrypted = crypto_ctx.decrypt(crypto_ctx.encrypt(crypto_container))
        self.assertEqual(str(crypto_container), decrypted)
        self.assertFalse(str(crypto_container).startswith(plaintext))

    def test_cleartext_message_matches_decrypted_message_with_stream_cipher(self):
        # RSA_WITH_RC4_128_SHA
        cipher_suite = 0x5
        plaintext = "a" * 32
        sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.version = tls.TLSVersion.TLS_1_0
        tls_ctx.sec_params = sec_params
        tls_ctx.client_ctx.sym_keystore = sec_params.client_keystore
        tls_ctx.server_ctx.sym_keystore = sec_params.server_keystore
        self.assertEqual(sec_params.master_secret, self.master_secret)
        crypto_ctx = tlsc.StreamCryptoContext(tls_ctx, tls_ctx.client_ctx)
        tls_ctx.client_ctx.crypto_ctx = crypto_ctx
        crypto_container = tlsc.CBCCryptoContainer.from_data(tls_ctx, tls_ctx.client_ctx, plaintext)
        decrypted = crypto_ctx.decrypt(crypto_ctx.encrypt(crypto_container))
        self.assertEqual(str(crypto_container), decrypted)
        self.assertTrue(str(crypto_container).startswith(plaintext))

    def test_hmac_used_matches_selected_ciphersuite(self):
        import struct
        # RSA_WITH_3DES_EDE_CBC_SHA
        cipher_suite = 0xa
        plaintext = "a" * 32
        sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.version = tls.TLSVersion.TLS_1_0
        tls_ctx.sec_params = sec_params
        tls_ctx.client_ctx.sym_keystore = sec_params.client_keystore
        self.assertEqual(sec_params.master_secret, self.master_secret)

        crypto_ctx = tlsc.CBCCryptoContext(tls_ctx, tls_ctx.client_ctx)
        # Pycryptodome does not expose the mode attribute
        # self.assertEqual(client_enc_cipher.mode, DES3.MODE_CBC)
        crypto_data = tlsc.CryptoData.from_context(tls_ctx, tls_ctx.client_ctx, plaintext)
        crypto_container = tlsc.CBCCryptoContainer.from_context(tls_ctx, tls_ctx.client_ctx, crypto_data)

        sequence_ = struct.pack("!Q", crypto_data.sequence)
        content_type_ = struct.pack("!B", crypto_data.content_type)
        version_ = struct.pack("!H", crypto_data.version)
        len_ = struct.pack("!H", crypto_data.data_len)
        digest_input = "%s%s%s%s%s" % (sequence_, content_type_, version_, len_, plaintext)

        self.assertEqual(crypto_container.mac,
                         HMAC.new(sec_params.client_keystore.hmac, digest_input, digestmod=SHA).digest())
        decrypted = crypto_ctx.decrypt(crypto_ctx.encrypt(crypto_container))
        self.assertEqual(str(crypto_container), decrypted)
        self.assertTrue(str(crypto_container).startswith(plaintext))

    def test_tls_1_1_and_above_cbc_iv_is_null(self):
        # RSA_WITH_AES_128_CBC_SHA
        cipher_suite = 0x2f
        sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.version = tls.TLSVersion.TLS_1_1
        tls_ctx.requires_iv = True
        tls_ctx.sec_params = sec_params
        # Creating the CryptoContext will set the IV to null if required
        tlsc.CBCCryptoContext(tls_ctx, tls_ctx.client_ctx)
        tlsc.CBCCryptoContext(tls_ctx, tls_ctx.server_ctx)
        self.assertEqual(tls_ctx.client_ctx.sym_keystore.iv, "\x00" * 16)
        self.assertEqual(tls_ctx.server_ctx.sym_keystore.iv, "\x00" * 16)

    def test_sec_params_generated_from_ms_match_sec_params_generated_from_pms(self):
        cipher_suite = 0x2f
        pms_params = tlsc.TLSSecurityParameters.from_pre_master_secret(self.prf, cipher_suite, self.pre_master_secret,
                                                                       self.client_random, self.server_random)
        ms_params = tlsc.TLSSecurityParameters.from_master_secret(self.prf, cipher_suite, self.master_secret,
                                                                  self.client_random, self.server_random)
        self.assertEqual("", ms_params.pms)
        self.assertEqual(pms_params.master_secret, ms_params.master_secret)
        self.assertEqual(pms_params.client_keystore.iv, ms_params.client_keystore.iv)
        self.assertEqual(pms_params.client_keystore.key, ms_params.client_keystore.key)
        self.assertEqual(pms_params.client_keystore.hmac, ms_params.client_keystore.hmac)
        self.assertEqual(pms_params.server_keystore.iv, ms_params.server_keystore.iv)
        self.assertEqual(pms_params.server_keystore.key, ms_params.server_keystore.key)
        self.assertEqual(pms_params.server_keystore.hmac, ms_params.server_keystore.hmac)

    def test_load_rsa_privkey_from_pem_file(self):
        pem_file = env_local_file("openssl_1_0_1_f_server.pem")
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.server_ctx.load_rsa_keys_from_file(pem_file)
        self.assertTrue(tls_ctx.server_ctx.asym_keystore.private)
        self.assertTrue(tls_ctx.server_ctx.asym_keystore.public)


class TestNullCompression(unittest.TestCase):

    def test_null_compression_returns_input_on_compress(self):
        null_compression = tlsc.NullCompression()
        input_ = "some text"
        self.assertEqual(null_compression.compress(input_), input_)

    def test_null_compression_returns_input_on_decompress(self):
        null_compression = tlsc.NullCompression()
        input_ = "some text"
        self.assertEqual(null_compression.decompress(input_), input_)


class TestTLSCompressionParameters(unittest.TestCase):

    def test_input_message_matches_decompressed_message_with_deflate(self):
        # DEFLATE
        compression_method = 0x1
        comp_method = tlsc.TLSCompressionParameters.comp_params[compression_method]["type"]
        input_ = "some other text"
        self.assertEqual(comp_method.decompress(comp_method.compress(input_)), input_)

    def test_input_message_matches_decompressed_message_with_null(self):
        # DEFLATE
        compression_method = 0x0
        comp_method = tlsc.TLSCompressionParameters.comp_params[compression_method]["type"]
        input_ = "some other text"
        self.assertEqual(comp_method.decompress(comp_method.compress(input_)), input_)


class TestCryptoContainer(unittest.TestCase):

    def setUp(self):
        self._do_kex(tls.TLSVersion.TLS_1_0)
        unittest.TestCase.setUp(self)

    def _do_kex(self, version):
        self.pem_priv_key = """-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDDLrmt4lKRpm6P
2blptwJsa1EBuxuuAayLjwNqKGvm5c1CAUEa/NtEpUMM8WYKRDwxzakUIGI/BdP3
NOEMphcs5+OekgJLhzoSdtAIrXPy8JIidENZE6FzCJ2b6fHU5O4hoNvv1Bx5yoZr
HVaWJIZMRRocJJ0Nf9oMaU8IE6m6OdBzQHEwcnL2/a8Q3VxstHufzjILmaZD9WL+
6AESlQMKZPNQ+Xd7d4nvnVkY4ZV46tA+KvADGuotgovQwG+uiyQoGRrQUms21vHF
zIvd3G9OCiyCTCHSyfsE3g7tks33NZ8O8gF8xa9OmU9TQPwwAyUr6JQXz0CW77o7
Cr9LpHuNAgMBAAECggEBAJRbMbtfqc8XqDYjEfGur2Lld19Pb0yl7RbvD3NjYhDR
X2DqPyhaRfg5fWubGSp4jyBz6C5qJwMsVN80DFNm83qoj7T52lC6aoOaV6og3V8t
SIZzxLUyXKdpRxM5kR13HSHmeQYkPbi9HcrRM/1PqdzTMXNuyQl3wq9oZDAJchsf
fmoh080htkaxhEb1bMXa2Lj7j2OIkHOsQeIu6BdbxIKRPIT+zrcklE6ocW8fTWAS
Qi3IZ1FYLL+fs6TTxjx0VkC8QLaxWxY0pqTiwS7ndZiZKc3l3ARuvRk8buP+X3Jg
BD86FQ18OXZC9boMbDbzv2cOLtdkq5pS3lJE4F9gjYECgYEA69ukU2pNWot2OPwK
PuPwAXWNrvnvFzQgIc0qOiCmgKJU6wqunlop4Bx5XmetHExVyJVBEhaHoDr0F3Rs
gt8IclKDsWGXoVcgfu3llMimiZ05hOf/XtcGTCZwZenMQ30cFh4ZRuUu7WCZ9tqO
28P8jCXB3IcaRpRnNvVvmCr5NXECgYEA09nUzRW993SlohceRW2C9fT9HZ4BaPWO
5wVlnoo5mlUfAyzl+AGT/WlKmrn/1gAHIznQJ8ZIABQvPaBXhvkANXZP5Ie0lObw
jA7qFuKt7yV4GGlDnU1MOLh+acABMQBGSx8BJDaomH7glTiPEPTZjoP6wfAsd1uv
Knjt7jH2ad0CgYEAx9ghknRd+rx0fbBBVix4riPW20324ihOmZVnlD0aF6B0Z3tz
ncUz+irmQ7GBIpsjjIO60QK6BHAvZrhFQVaNp6B26ZORkSlr5WDZyImDYtMPa6fP
36I+OcPQNOo3I3Acnjj+ne2PJ59Ula92oIudr3pGmv72qpsQIacw2TSAWGECgYEA
sdNAN+HPMn68ZaGoLDjvW8uIB6tQnay5hhvWn8yA65YV0RGH+7Q/Z9BQ6i3EnPor
A5uMqUZbu4011jHYJpiuXzHvf/GVWAO92KLQReOCgqHd/Aen1MtEdrwOiG+90Ebd
ukLNL3ud61tc4oS2OlJ8p48LFm2mtY3FLA6UEYPoxhUCgYEAtsfWIGnBh7XC+HwI
2higSgN92VpJHSPOyOi0aG/u5AEQ+fsCUIi3KakxzvmiGMAEvWItkKyz2Gu8smtn
2HVsGxI5UW7aLw9s3qe8kyMSfUk6pGamVhJUQmDr77+5zEzykPBxwGwDwdeR43CR
xVgf/Neb/avXgIgi6drj8dp1fWA=
-----END PRIVATE KEY-----
        """
        rsa_priv_key = RSA.importKey(self.pem_priv_key)
        self.priv_key = PKCS1_v1_5.new(rsa_priv_key)
        self.pub_key = PKCS1_v1_5.new(rsa_priv_key.publickey())

        self.tls_ctx = tlsc.TLSSessionCtx()
        self.tls_ctx.server_ctx.load_rsa_keys(self.pem_priv_key)
        # SSLv2
        self.record_version = 0x0002
        self.version = version
        # RSA_WITH_AES_128_SHA
        self.cipher_suite = tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA
        # DEFLATE
        self.comp_method = tls.TLSCompressionMethod.NULL
        self.client_hello = tls.TLSRecord(version=self.record_version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(
            version=version, compression_methods=[self.comp_method], cipher_suites=[self.cipher_suite])])
        self.tls_ctx.insert(self.client_hello)
        self.server_hello = tls.TLSRecord(version=self.version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(
            version=version, compression_method=self.comp_method, cipher_suite=self.cipher_suite)])
        self.tls_ctx.insert(self.server_hello)
        # Build method to generate EPMS automatically in TLSSessionCtx
        self.client_kex = tls.TLSRecord(version=self.version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() /
            tls.TLSClientRSAParams(data=self.tls_ctx.get_encrypted_pms())])
        self.tls_ctx.insert(self.client_kex)

    def test_crypto_container_increments_sequence_number(self):
        client_seq_num = self.tls_ctx.client_ctx.sequence
        server_seq_num = self.tls_ctx.server_ctx.sequence
        client_crypto_ctx = tlsc.CBCCryptoContext(self.tls_ctx, self.tls_ctx.client_ctx)
        client_crypto_ctx.encrypt_data(b"")
        client_seq_num += 1
        self.assertEqual(self.tls_ctx.client_ctx.sequence, client_seq_num)
        self.assertEqual(self.tls_ctx.server_ctx.sequence, server_seq_num)
        self.tls_ctx.client = False
        client_crypto_ctx = tlsc.CBCCryptoContext(self.tls_ctx, self.tls_ctx.server_ctx)
        client_crypto_ctx.encrypt_data(b"")
        self.assertEqual(self.tls_ctx.client_ctx.sequence, client_seq_num)
        self.assertEqual(self.tls_ctx.server_ctx.sequence, server_seq_num + 1)

    def test_cbc_crypto_container_str_returns_cipher_payload(self):
        data = b"abcde"
        crypto_data = tlsc.CryptoData.from_context(self.tls_ctx, self.tls_ctx.client_ctx, data)
        crypto_container = tlsc.CBCCryptoContainer.from_context(self.tls_ctx, self.tls_ctx.client_ctx, crypto_data)
        padding = crypto_container.padding
        self.assertEqual("%s%s%s%s" % (data, crypto_container.mac, padding, chr(len(padding))), str(crypto_container))

    def test_cbc_cipher_payload_is_block_size_aligned(self):
        data = b"A" * 1025
        crypto_data = tlsc.CryptoData.from_context(self.tls_ctx, self.tls_ctx.client_ctx, data)
        crypto_container = tlsc.CBCCryptoContainer.from_context(self.tls_ctx, self.tls_ctx.client_ctx, crypto_data)
        self.assertTrue(len(crypto_container) % AES.block_size == 0)

    def test_crypto_container_returns_ciphertext(self):
        data = b"C" * 102
        self.tls_ctx.client = False
        crypto_container = tlsc.CBCCryptoContainer.from_data(self.tls_ctx, self.tls_ctx.server_ctx, data)
        cleartext = str(crypto_container)
        crypto_ctx = tlsc.CBCCryptoContext(self.tls_ctx, self.tls_ctx.server_ctx)
        ciphertext = crypto_ctx.encrypt_data(data)
        self.assertEqual(cleartext, crypto_ctx.decrypt(ciphertext))

    def test_generated_mac_can_be_overiden(self):
        data = b"C" * 102
        self.tls_ctx.client = False
        crypto_container = tlsc.CBCCryptoContainer.from_context(self.tls_ctx, self.tls_ctx.server_ctx,
                                                                tlsc.CryptoData.from_context(self.tls_ctx,
                                                                                             self.tls_ctx.server_ctx,
                                                                                             data))
        initial_mac = crypto_container.mac
        crypto_container.mac = "1234"
        self.assertNotEqual(initial_mac, crypto_container.mac)

    def test_tls_1_1_and_above_has_a_random_explicit_iv_with_block_cipher(self):
        data = b"C" * 102
        self._do_kex(tls.TLSVersion.TLS_1_1)
        crypto_container = tlsc.CBCCryptoContainer.from_data(self.tls_ctx, self.tls_ctx.server_ctx, data)
        self.assertNotEqual(crypto_container.explicit_iv, b"")
        self.assertEqual(len(crypto_container.explicit_iv), AES.block_size)
        self.assertTrue(str(crypto_container).startswith(crypto_container.explicit_iv))

    def test_tls_1_0_and_below_has_no_explicit_iv(self):
        data = b"C" * 102
        crypto_container = tlsc.CBCCryptoContainer.from_data(self.tls_ctx, self.tls_ctx.server_ctx, data)
        self.assertEqual(crypto_container.explicit_iv, "")
        self.assertTrue(str(crypto_container).startswith(data))


class TestTLSPRF(unittest.TestCase):

    def _initialize_tls1_known_params(self):
        self.pms = binascii.unhexlify(
            "03010555c6b01b9e47d803058dc33fe49175064811b06192bb40a0b732b99b5fe5fdc113b5520dcb7fc97bb43aadd231")
        self.ms = binascii.unhexlify(
            "f59ea7a04a13483ee024096840b3d3b8fb2c5a9cddf205f148790469b165421caacd5b32743265090307f6479170c248")
        self.client_random = binascii.unhexlify("55b1285b1332a91c75b9822135f3cb729c9a62f30ce296032a872719092df119")
        self.server_random = binascii.unhexlify("0774c311aa283e218d4c0d20561829fda850d92d022a4bdb56bc185ea4e2a5a3")
        # SHA1 - 20 bytes
        self.client_mac = binascii.unhexlify("6a88b5e508875c425200c38f9110840ea0fc7cf5")
        # AES - 16 bytes
        self.client_key = binascii.unhexlify("53606e034295c9ccd50d84d60d8fea9c")
        self.client_iv = binascii.unhexlify("4ffdf70f8dbdd6dcebb1b246cbb4a36b")
        # SHA1 - 20 bytes
        self.server_mac = binascii.unhexlify("9042c763e49a6876173a0837d47263bce4da5703")
        # AES - 16 bytes
        self.server_key = binascii.unhexlify("95c4ee054377d9e7006a8da970e95630")
        self.server_iv = binascii.unhexlify("4f4f168ced384533cb47cfdf3ecaf3ef")

    def _initialize_tls1_2_known_params(self):
        self.pms = binascii.unhexlify(
            "0303e29757f8ab24ebb42c52fb866b28a188860b726cff663456e8f37d563ae006b167df5d984acba621bd65c583ac32")
        self.ms = binascii.unhexlify(
            "05a7e4735508e45f8870bc27bb0e69f3ea4e41a54c1de0a7d30ac73daf90dbd0cf9f6d182a6b69b6365b4c9cc7112b6c")
        self.client_random = binascii.unhexlify("55b1698489a180cfc3360aff54c31d90accbaf12b53b3e84ec71b8895c524e8e")
        self.server_random = binascii.unhexlify("38d34ea6e7cd7d9e76a3cff629421ef32274bd40b7483e879be2e81c3c344997")
        # SHA1 - 20 bytes
        self.client_mac = binascii.unhexlify("8dad197710c3b8c29121ec833556cf1cfdeb5e67")
        # AES - 16 bytes
        self.client_key = binascii.unhexlify("91e0f55dc0c6661dbf33b91187fc84b7")
        # SHA1 - 20 bytes
        self.server_mac = binascii.unhexlify("e076da857da6a750ee72b690afe70b6cff32c8ef")
        # AES - 16 bytes
        self.server_key = binascii.unhexlify("ef99d0b6f1316163c2a82f585ab2670b")

    def test_tls1_0_prf_against_static_data(self):
        self._initialize_tls1_known_params()
        prf = tlsc.TLSPRF(tls.TLSVersion.TLS_1_0)
        self.assertEqual(prf.get_bytes(self.pms, tlsc.TLSPRF.TLS_MD_MASTER_SECRET_CONST,
                                       "%s%s" % (self.client_random, self.server_random), 48), self.ms)
        crypto_material_len = len(self.client_mac) + len(self.client_key) + len(self.client_iv)
        crypto_material = prf.get_bytes(self.ms, tlsc.TLSPRF.TLS_MD_KEY_EXPANSION_CONST,
                                        "%s%s" % (self.server_random, self.client_random), 2 * crypto_material_len)
        i = 0
        self.assertEqual(self.client_mac, crypto_material[i:len(self.client_mac)])
        i += len(self.client_mac)
        self.assertEqual(self.server_mac, crypto_material[i:i + len(self.server_mac)])
        i += len(self.server_mac)
        self.assertEqual(self.client_key, crypto_material[i:i + len(self.client_key)])
        i += len(self.client_key)
        self.assertEqual(self.server_key, crypto_material[i:i + len(self.server_key)])
        i += len(self.server_key)
        self.assertEqual(self.client_iv, crypto_material[i:i + len(self.client_iv)])
        i += len(self.client_iv)
        self.assertEqual(self.server_iv, crypto_material[i:i + len(self.server_iv)])
        i += len(self.server_iv)

    def test_tls1_2_prf_against_static_data(self):
        self._initialize_tls1_2_known_params()
        prf = tlsc.TLSPRF(tls.TLSVersion.TLS_1_2)
        self.assertEqual(prf.get_bytes(self.pms, tlsc.TLSPRF.TLS_MD_MASTER_SECRET_CONST,
                                       "%s%s" % (self.client_random, self.server_random), 48), self.ms)
        crypto_material_len = len(self.client_mac) + len(self.client_key)
        crypto_material = prf.get_bytes(self.ms, tlsc.TLSPRF.TLS_MD_KEY_EXPANSION_CONST,
                                        "%s%s" % (self.server_random, self.client_random), 2 * crypto_material_len)
        i = 0
        self.assertEqual(self.client_mac, crypto_material[i:len(self.client_mac)])
        i += len(self.client_mac)
        self.assertEqual(self.server_mac, crypto_material[i:i + len(self.server_mac)])
        i += len(self.server_mac)
        self.assertEqual(self.client_key, crypto_material[i:i + len(self.client_key)])
        i += len(self.client_key)
        self.assertEqual(self.server_key, crypto_material[i:i + len(self.server_key)])
        i += len(self.server_key)
        # No IVs for TLS1.2

    def test_tls_1_1_defined_prf_raises_error(self):
        with self.assertRaises(ValueError):
            tlsc.TLSPRF(tls.TLSVersion.TLS_1_1, SHA)

    def test_tls_1_2_cipher_specified_prf_is_used(self):
        prf = tlsc.TLSPRF(tls.TLSVersion.TLS_1_2, SHA384)
        self.assertEqual(prf.digest, SHA384)


class TestEAEADCryptoContext(unittest.TestCase):
    def setUp(self):
        cipher_suite = tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256
        self.tls_ctx = tlsc.TLSSessionCtx()
        self.tls_ctx.negotiated.version = tls.TLSVersion.TLS_1_2
        self.tls_ctx.server_ctx.sequence = 5
        self.tls_ctx.server_ctx.nonce = 72623859790382856
        self.ctx = self.tls_ctx.server_ctx
        self.prf = tlsc.TLSPRF(tls.TLSVersion.TLS_1_0)
        self.pre_master_secret = "\x03\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
        self.client_random = "a" * 32
        self.server_random = "z" * 32
        self.master_secret = binascii.unhexlify(
            "43278712b1feba3622c5745f79908a77b6e801239fc19390240cc45a17517b6218dfcb3f370c97f15329251e7a20ffb0")
        self.tls_ctx.sec_params = tlsc.TLSSecurityParameters.from_master_secret(self.prf, cipher_suite,
                                                                                self.master_secret,
                                                                                self.client_random, self.server_random)
        self.tls_ctx.server_ctx.sym_keystore = self.tls_ctx.sec_params.server_keystore
        self.tls_ctx.client_ctx.sym_keystore = self.tls_ctx.sec_params.client_keystore
        unittest.TestCase.setUp(self)

    def test_when_EAEAD_crypto_container_is_built_aead_is_generated(self):
        plaintext = b"1234"
        crypto_container = tlsc.EAEADCryptoContainer.from_data(self.tls_ctx, self.ctx, plaintext)
        self.assertEqual(str(crypto_container), plaintext)
        self.assertTrue(crypto_container.aead != b"")
        self.assertTrue(crypto_container.aead.startswith(struct.pack("!Q", 5)))
        with self.assertRaises(AttributeError):
            crypto_container.padding
        with self.assertRaises(AttributeError):
            crypto_container.mac

    def test_when_EAEAD_crypto_context_is_used_security_parameters_are_set(self):
        self.assertEqual(len(self.tls_ctx.client_ctx.sym_keystore.iv), 4)
        self.assertEqual(self.tls_ctx.client_ctx.sym_keystore.iv, "\xd4\x80\xd0\xa8")
        self.assertEqual(len(self.tls_ctx.server_ctx.sym_keystore.iv), 4)
        self.assertEqual(self.tls_ctx.server_ctx.sym_keystore.iv, "a\xa6\x1f1")
        self.assertEqual(len(self.tls_ctx.client_ctx.sym_keystore.hmac), 0)
        self.assertEqual(self.tls_ctx.client_ctx.sym_keystore.hmac, "")
        self.assertEqual(len(self.tls_ctx.server_ctx.sym_keystore.hmac), 0)
        self.assertEqual(self.tls_ctx.server_ctx.sym_keystore.hmac, "")
        self.assertEqual(len(self.tls_ctx.client_ctx.sym_keystore.key), 16)
        self.assertEqual(self.tls_ctx.client_ctx.sym_keystore.key, "\xe1: \xc6\'\"h\x9bF\x82\xc3\xbd\xa0~I\xd0")
        self.assertEqual(len(self.tls_ctx.server_ctx.sym_keystore.key), 16)
        self.assertEqual(self.tls_ctx.server_ctx.sym_keystore.key, "\xda\xa7{\xcb&\xd3\xfb\xe3\x1f\xb3v2\xa9\\?\xa6")

    def test_when_EAEAD_crypto_context_is_used_nonce_is_incremented(self):
        plaintext = b"1234"
        initial_nonce = self.tls_ctx.server_ctx.nonce
        initial_seq = self.tls_ctx.server_ctx.sequence
        crypto_ctx = tlsc.EAEADCryptoContext(self.tls_ctx, self.ctx)
        ciphertext = crypto_ctx.encrypt_data(plaintext)
        self.assertEqual(initial_nonce + 1, self.tls_ctx.server_ctx.nonce)
        self.assertEqual(initial_seq + 1, self.tls_ctx.server_ctx.sequence)
        # Mac check will fail, since sequence number has incremented
        warnings.filterwarnings("error")
        with self.assertRaises(Warning):
            decrypted = crypto_ctx.decrypt(ciphertext)
        # Now, rewind the state to the correct sequence number, MAC check will succeed
        self.ctx.sequence = 5
        decrypted = crypto_ctx.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted[8: 8 + len(plaintext)])


class TestHKDF(unittest.TestCase):
    """Test vectors taken from here: https://tools.ietf.org/html/rfc5869"""
    def test_rfc5869_test_case_1(self):
        ikm = binascii.unhexlify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = binascii.unhexlify("000102030405060708090a0b0c")
        info = binascii.unhexlify("f0f1f2f3f4f5f6f7f8f9")
        len_ = 42
        prk = binascii.unhexlify("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = binascii.unhexlify("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        hkdf = tlsc.HKDF(SHA256).extract(ikm, salt)
        self.assertEqual(len(hkdf.prk), SHA256.digest_size)
        self.assertEqual(hkdf.prk, prk)
        bytes_ = hkdf.expand(len_, info)
        self.assertEqual(len(bytes_), len_)
        self.assertEqual(bytes_, okm)

    def test_rfc5869_test_case_2(self):
        ikm = binascii.unhexlify(("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                                  "404142434445464748494a4b4c4d4e4f"))
        salt = binascii.unhexlify(("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                                   "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                                   "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
        info = binascii.unhexlify(("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                   "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
        len_ = 82
        prk = binascii.unhexlify("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
        okm = binascii.unhexlify(("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                                  "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                                  "cc30c58179ec3e87c14c01d5c1f3434f1d87"))
        hkdf = tlsc.HKDF(SHA256).extract(ikm, salt)
        self.assertEqual(len(hkdf.prk), SHA256.digest_size)
        self.assertEqual(hkdf.prk, prk)
        bytes_ = hkdf.expand(len_, info)
        self.assertEqual(len(bytes_), len_)
        self.assertEqual(bytes_, okm)

    def test_rfc5869_test_case_3(self):
        ikm = binascii.unhexlify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = binascii.unhexlify("")
        info = binascii.unhexlify("")
        len_ = 42
        prk = binascii.unhexlify("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        okm = binascii.unhexlify("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        hkdf = tlsc.HKDF(SHA256).extract(ikm, salt)
        self.assertEqual(len(hkdf.prk), SHA256.digest_size)
        self.assertEqual(hkdf.prk, prk)
        bytes_ = hkdf.expand(len_, info)
        self.assertEqual(len(bytes_), len_)
        self.assertEqual(bytes_, okm)

    def test_rfc5869_test_case_5(self):
        ikm = binascii.unhexlify(("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                  "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                                  "404142434445464748494a4b4c4d4e4f"))
        salt = binascii.unhexlify(("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                                   "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                                   "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
        info = binascii.unhexlify(("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                   "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
        len_ = 82
        prk = binascii.unhexlify("8adae09a2a307059478d309b26c4115a224cfaf6")
        okm = binascii.unhexlify(("0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe"
                                  "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e"
                                  "927336d0441f4c4300e2cff0d0900b52d3b4"))
        hkdf = tlsc.HKDF(SHA).extract(ikm, salt)
        self.assertEqual(len(hkdf.prk), SHA.digest_size)
        self.assertEqual(hkdf.prk, prk)
        bytes_ = hkdf.expand(len_, info)
        self.assertEqual(len(bytes_), len_)
        self.assertEqual(bytes_, okm)

    def test_rfc5869_test_case_7(self):
        ikm = binascii.unhexlify("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
        len_ = 42
        prk = binascii.unhexlify("2adccada18779e7c2077ad2eb19d3f3e731385dd")
        okm = binascii.unhexlify("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48")
        hkdf = tlsc.HKDF(SHA).extract(ikm)
        self.assertEqual(len(hkdf.prk), SHA.digest_size)
        self.assertEqual(hkdf.prk, prk)
        bytes_ = hkdf.expand(len_)
        self.assertEqual(len(bytes_), len_)
        self.assertEqual(bytes_, okm)


class TestTLS13PRF(unittest.TestCase):
    """Test vectors taken from https://tools.ietf.org/html/draft-thomson-tls-tls13-vectors-00"""
    def setUp(self):
        self.client_hello = tls.TLSRecord(binascii.unhexlify(b"16030100fa010000f603034a772c764c3313f344b2f4fae943e816fe5af3eac7"
                                                             b"4809c21e2c24989f3e8c5200003e130113031302c02bc02fcca9cca8c00ac009"
                                                             b"c013c023c027c014009eccaa00330032006700390038006b00160013009c002f"
                                                             b"003c0035003d000a000500040100008f0000000b0009000006736572766572ff"
                                                             b"01000100000a00140012001d00170018001901000101010201030104000b0002"
                                                             b"010000230000002800260024001d0020e122b20099cbe5059a9bbe5880e02ed6"
                                                             b"525d6f72f8f7afabb87a32dbe9e23022002b0007067f1003030302000d002000"
                                                             b"1e040305030603020308040805080604010501060102010402050206020202"))
        # missing test vector for server_hello
        # self.server_hello = tls.TLSRecord()
        self.hello_hash = binascii.unhexlify(b"79027f438271dba2d8e207b6e36a5180bdd916869ab43f24f2e2fa98b2db135c")
        self.handshake_hash = binascii.unhexlify(b"16756399da565370337a4ede5774b9e60bf328086272dc393b8b1d8ba6e6ebbb")
        self.client_finish_hash = binascii.unhexlify(b"e74cc34c780d9562b1b3e7321f2ebcb0e6646246dbae060d5d1335ac5f8db917")
        unittest.TestCase.setUp(self)

    def test_when_1rtt_is_used_then_test_vectors_are_generated(self):
        early_secret = binascii.unhexlify(b"33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        # This is the computed ECDH shared secret (old master secret)
        ec_ikm = binascii.unhexlify(b"0dfa4c5e11a6f606d4b75f138412d85a4b2da0d5f981ffc1d2e8ceff2e00a12c")
        handshake_secret = binascii.unhexlify(b"1b3f45dcdc375a9ae91bf34d669f24c753132f1d394553afbfffe6568a27e22c")
        master_secret = binascii.unhexlify(b"cab4645a3995d0d85bea9942596284e72058a3d4d8f3e0d9885aa92c517ad9e4")
        client_handshake_secret = binascii.unhexlify(b"f737c2b29be2ef489d145dd3df48510386e812edcf79992527e9ad5479967193")
        server_handshake_secret = binascii.unhexlify(b"3550ca3a8c2192729cc385313e3bc83292a14f4ecb3d2b9218ea7907c67ab3a7")
        server_handshake_write_key = binascii.unhexlify(b"d2dd45f87ad87801a85ac38187f9023b")
        server_handshake_write_iv = binascii.unhexlify(b"f0a14f808692cef87a3daf70")
        finish = binascii.unhexlify(b"1ba8c586468bb93dcd9264e62929e77deba36e5bfc5e06ad029f667448e5e6c8")
        client_traffic_secret = binascii.unhexlify(b"2a1d25e6f9f13f92e4b482fa06bc44471218368d2d4e03e0504d4e342b16ff8f")
        # No test vectors for these elements
        server_traffic_secret = binascii.unhexlify(b"56231ff04300e7f74964da88c8bbdf1242a31ade351ce97446598d28632e79ca")
        server_traffic_write_key = binascii.unhexlify(b"3381f6b3f94500f16226de440193e858")
        server_traffic_write_iv = binascii.unhexlify(b"4f1d73cc1d465eb30021c41f")
        exporter_secret = binascii.unhexlify(b"407265d811f66c2430de0832fbc4bd25719a4736301f131298fd9107653a78f2")
        resumption_secret = binascii.unhexlify(b"05438edfa0f6e6630d7a9ffe81dc67736d753a4ee351a79d296975918b16039e")
        prf = tlsc.TLS13PRF(SHA256)
        early_secrets = prf.derive_early_secrets()
        self.assertEqual(early_secrets.early_secret, early_secret)

        handshake_secrets = prf.derive_handshake_secrets(ec_ikm, early_secrets.early_secret, self.hello_hash, {"key_len": 16, "iv_len": 12})
        self.assertEqual(handshake_secrets.handshake_secret, handshake_secret)
        self.assertEqual(handshake_secrets.client.secret, client_handshake_secret)
        self.assertEqual(handshake_secrets.server.secret, server_handshake_secret)
        self.assertEqual(handshake_secrets.server.write_key, server_handshake_write_key)
        self.assertEqual(handshake_secrets.server.write_iv, server_handshake_write_iv)

        computed_finish = prf.derive_finish_secret(handshake_secrets.server.secret)
        self.assertEqual(computed_finish, finish)

        computed_resumption_secret = prf.derive_resumption_secret(handshake_secrets.handshake_secret, self.client_finish_hash)
        self.assertEqual(computed_resumption_secret, resumption_secret)

        master_secrets = prf.derive_traffic_secrets(handshake_secrets.handshake_secret, self.handshake_hash, {"key_len": 16, "iv_len": 12})
        self.assertEqual(master_secrets.master_secret, master_secret)
        self.assertEqual(master_secrets.client.secret, client_traffic_secret)
        self.assertEqual(master_secrets.server.secret, server_traffic_secret)
        self.assertEqual(master_secrets.server.write_key, server_traffic_write_key)
        self.assertEqual(master_secrets.server.write_iv, server_traffic_write_iv)
        self.assertEqual(master_secrets.exporter_secret, exporter_secret)


if __name__ == "__main__":
    unittest.main()
