#! -*- coding: utf-8 -*-

import os
import binascii
import unittest
import scapy_ssl_tls.ssl_tls as tls
import scapy_ssl_tls.ssl_tls_crypto as tlsc
from Crypto.Hash import HMAC, MD5, SHA
from Crypto.Cipher import AES, DES3, PKCS1_v1_5
from Crypto.PublicKey import RSA

def env_local_file(file):
    return os.path.join(os.path.dirname(__file__),'files',file)

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
        unittest.TestCase.setUp(self)

    def test_negotiated_cipher_is_used_in_context(self):
        # RSA_WITH_NULL_MD5
        cipher_suite = 0x1
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello(gmt_unix_time=123456, random_bytes="A"*28, cipher_suite=cipher_suite)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.params.negotiated.key_exchange, tlsc.TLSSecurityParameters.crypto_params[cipher_suite]["key_exchange"]["name"])
        self.assertEqual(tls_ctx.params.negotiated.mac, tlsc.TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["name"])

    def test_negotiated_compression_method_is_used_in_context(self):
        # DEFLATE
        compression_method = 0x1
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello(gmt_unix_time=123456, random_bytes="A"*28, compression_method=compression_method)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.params.negotiated.compression_algo, tlsc.TLSCompressionParameters.comp_params[compression_method]["name"])
        input_ = "some data" * 16
        self.assertEqual(tls_ctx.compression.method.decompress(tls_ctx.compression.method.compress(input_)), input_)

    def test_encrypted_pms_is_only_available_after_server_certificate_is_presented(self):
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientHello()
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        with self.assertRaises(ValueError):
            tls_ctx.get_encrypted_pms()

    def test_encrypting_pms_fails_if_no_certificate_in_connection(self):
        tls_ctx = tlsc.TLSSessionCtx()
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientHello(version=0x0301)
        tls_ctx.insert(pkt)
        with self.assertRaises(ValueError):
            tls_ctx.get_encrypted_pms()

    def test_random_pms_is_generated_on_client_hello(self):
        tls_ctx = tlsc.TLSSessionCtx()
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientHello(version=0x0301)
        tls_ctx.insert(pkt)
        self.assertIsNotNone(tls_ctx.crypto.session.premaster_secret)

    def test_keys_are_set_in_context_when_loaded(self):
        tls_ctx = tlsc.TLSSessionCtx()
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientHello(version=0x0301)
        tls_ctx.insert(pkt)
        tls_ctx.rsa_load_keys(self.pem_priv_key)
        self.assertIsNotNone(tls_ctx.crypto.server.rsa.privkey)
        self.assertIsNotNone(tls_ctx.crypto.server.rsa.pubkey)
        # Broken due to pycrypto bug: https://github.com/dlitz/pycrypto/issues/114
        # Uncomment when fixed upstream
        #self.assertTrue(tls_ctx.crypto.server.rsa.privkey.can_decrypt())
        #self.assertTrue(tls_ctx.crypto.server.rsa.pubkey.can_decrypt())
        self.assertTrue(tls_ctx.crypto.server.rsa.privkey.can_encrypt())
        # TODO: Invertigate further: broken also in pycrypto. Should return False for public keys.
        # self.assertFalse(tls_ctx.crypto.server.rsa.pubkey.can_encrypt())

    def test_decrypted_pms_matches_generated_pms(self):
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.rsa_load_keys(self.pem_priv_key)
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientHello()
        tls_ctx.insert(pkt)
        epms = tls_ctx.get_encrypted_pms()
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello()
        tls_ctx.insert(pkt)
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientKeyExchange(data=epms)
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.crypto.session.encrypted_premaster_secret, epms)
        self.assertEqual(tls_ctx.crypto.session.premaster_secret, self.priv_key.decrypt(epms, None))

    def test_fixed_crypto_data_matches_verify_data(self):
        verify_data = "12003ac89553b7a233da64b9"
        tls_ctx = tlsc.TLSSessionCtx()
        #tls_ctx.rsa_load_keys(self.pem_priv_key)
        client_hello = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientHello(gmt_unix_time=1234, random_bytes="A"*28)
        tls_ctx.insert(client_hello)
        tls_ctx.crypto.session.premaster_secret = "B"*48
        epms = "C"*256
        server_hello = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello(gmt_unix_time=1234, random_bytes="A"*28)
        tls_ctx.insert(server_hello)
        client_kex = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSClientKeyExchange(data=epms)
        tls_ctx.insert(client_kex)
        self.assertEqual(binascii.hexlify(tls_ctx.get_verify_data()), verify_data)

    def test_client_dh_parameters_generateion_matches_fixed_data(self):
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.crypto.server.dh.p = "\xdaX<\x16\xd9\x85\"\x89\xd0\xe4\xafuoL\xca\x92\xddK\xe53\xb8\x04\xfb\x0f\xed\x94\xef\x9c\x8aD\x03\xedWFP\xd3i\x99\xdb)\xd7v\'k\xa2\xd3\xd4\x12\xe2\x18\xf4\xdd\x1e\x08L\xf6\xd8\x00>|Gt\xe83"
        tls_ctx.crypto.server.dh.g = "\x02"
        tls_ctx.crypto.server.dh.y_s = "b\x1bF\xd4\xbe\xc6\x83d\x80\x1e\xeam\x86^\xcc!\xb2\x1b\x85+\xbd$j\xc9\x05\xf4\x14\x82 7\x8f_\x13\xcb\xef\xabyd\xb4\xc8\xda\xde\xac\xe8Zr\x8f\xb5\xfc\n\x16\xb0b\xf7\xd9!\x8d\x03\xef\n\r9\xd8\x87"
        client_privkey = 5398526532442504864680398257365369432058147704829279760748758494328728516319L
        client_pubkey = tls_ctx.get_client_dh_pubkey(client_privkey)
        self.assertEqual("/T\xdc;\xc49\xa6\x8cD\xd4\xc1\x07I|\xb6\xc8\xaf\xb5\x04\xe9\xfb\t\x0e}\x14~\xa4\x1f\xdfo\x08u)Z\xb3\x0e\x1c^\xa3x0\x90\xa1\xd7\x82\x9dLT\xa6^\xcc\xf7\xae\x87\x97\x86vi\x02s\x10\xb3\xdbo", client_pubkey)
        self.assertEqual("}\xcae\xd2y\xd7F$\xde\"\xa9s\xfbNR9v\x19t9\x87\xa8\xa3\x9c\xccb]\x13\xb7\x8a\x8f\xdf\x7fv\x05\xa6\xf1\xa7\xc8\xf4X\xe3\xd4\xac\xd6\x1e4\xb4\x1cc\xbb\xce\xbe\x94lQ\x91\xb9\xde\xb7\xa6gu_", tls_ctx.crypto.session.premaster_secret)

class TestTLSSecurityParameters(unittest.TestCase):

    def setUp(self):
        self.pre_master_secret = "\x03\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
        self.client_random = "a" * 32
        self.server_random = "z" * 32
        self.master_secret = binascii.unhexlify("43278712b1feba3622c5745f79908a77b6e801239fc19390240cc45a17517b6218dfcb3f370c97f15329251e7a20ffb0")
        unittest.TestCase.setUp(self)

    def test_unsupported_cipher_suite_throws_exception(self):
        with self.assertRaises(RuntimeError):
            tlsc.TLSSecurityParameters(0xffff, self.pre_master_secret, self.client_random, self.server_random)

    def test_building_with_supported_cipher_sets_lengths(self):
        # RSA_WITH_AES_128_CBC_SHA
        cipher_suite = 0x2f
        sec_params = tlsc.TLSSecurityParameters(cipher_suite, self.pre_master_secret, self.client_random, self.server_random)
        self.assertEqual(sec_params.cipher_key_length, 16)
        self.assertEqual(sec_params.mac_key_length, SHA.digest_size)
        self.assertEqual(sec_params.iv_length, AES.block_size)

    def test_building_with_null_cipher_sets_lengths(self):
        #RSA_WITH_NULL_MD5
        cipher_suite = 0x1
        sec_params = tlsc.TLSSecurityParameters(cipher_suite, self.pre_master_secret, self.client_random, self.server_random)
        self.assertEqual(sec_params.cipher_key_length, 0)
        self.assertEqual(sec_params.mac_key_length, MD5.digest_size)
        self.assertEqual(sec_params.iv_length, tlsc.NullCipher.block_size)

    def test_cleartext_message_matches_decrypted_message_with_block_cipher(self):
        # RSA_WITH_AES_128_CBC_SHA
        cipher_suite = 0x2f
        sec_params = tlsc.TLSSecurityParameters(cipher_suite, self.pre_master_secret, self.client_random, self.server_random)
        self.assertEqual(sec_params.master_secret, self.master_secret)
        client_enc_cipher = sec_params.get_client_enc_cipher()
        client_dec_cipher = sec_params.get_client_dec_cipher()
        self.assertEqual(client_enc_cipher.mode, AES.MODE_CBC)
        plaintext = "a" * 32
        self.assertEqual(client_dec_cipher.decrypt(client_enc_cipher.encrypt(plaintext)), plaintext)

    def test_cleartext_message_matches_decrypted_message_with_stream_cipher(self):
        # RSA_WITH_RC4_128_SHA
        cipher_suite = 0x5
        sec_params = tlsc.TLSSecurityParameters(cipher_suite, self.pre_master_secret, self.client_random, self.server_random)
        self.assertEqual(sec_params.master_secret, self.master_secret)
        client_enc_cipher = sec_params.get_client_enc_cipher()
        client_dec_cipher = sec_params.get_client_dec_cipher()
        plaintext = "a" * 32
        self.assertEqual(client_dec_cipher.decrypt(client_enc_cipher.encrypt(plaintext)), plaintext)

    def test_hmac_used_matches_selected_ciphersuite(self):
        # RSA_WITH_3DES_EDE_CBC_SHA
        cipher_suite = 0xa
        sec_params = tlsc.TLSSecurityParameters(cipher_suite, self.pre_master_secret, self.client_random, self.server_random)
        self.assertEqual(sec_params.master_secret, self.master_secret)
        client_enc_cipher = sec_params.get_client_enc_cipher()
        client_dec_cipher = sec_params.get_client_dec_cipher()
        self.assertEqual(client_enc_cipher.mode, DES3.MODE_CBC)
        plaintext = "a" * 32
        self.assertEqual(client_dec_cipher.decrypt(client_enc_cipher.encrypt(plaintext)), plaintext)
        client_hmac = sec_params.get_client_hmac()
        client_hmac.update("some secret")
        self.assertEqual(client_hmac.hexdigest(), HMAC.new(sec_params.client_write_MAC_key, "some secret", digestmod=SHA).hexdigest())

    def test_tls_1_1_and_above_iv_is_null(self):
        # RSA_WITH_AES_128_CBC_SHA
        cipher_suite = 0x2f
        sec_params = tlsc.TLSSecurityParameters(cipher_suite, self.pre_master_secret, self.client_random, self.server_random, explicit_iv=True)
        self.assertEqual(sec_params.client_write_IV, "\x00"*16)
        self.assertEqual(sec_params.server_write_IV, "\x00"*16)

    def test_load_rsa_privkey_from_pem_file(self):
        pem_file = env_local_file("openssl_1_0_1_f_server.pem")
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.rsa_load_keys_from_file(pem_file)
        self.assertTrue(tls_ctx.crypto.server.rsa.privkey)
        self.assertTrue(tls_ctx.crypto.server.rsa.pubkey)

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
        self.tls_ctx.rsa_load_keys(self.pem_priv_key)
        # SSLv2
        self.record_version = 0x0002
        self.version = version
        # RSA_WITH_AES_128_SHA
        self.cipher_suite = tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA
        # DEFLATE
        self.comp_method = tls.TLSCompressionMethod.NULL
        self.client_hello = tls.TLSRecord(version=self.record_version)/tls.TLSHandshake()/tls.TLSClientHello(version=version, compression_methods=[self.comp_method], cipher_suites=[self.cipher_suite])
        self.tls_ctx.insert(self.client_hello)
        self.server_hello = tls.TLSRecord(version=self.version)/tls.TLSHandshake()/tls.TLSServerHello(version=version, compression_method=self.comp_method, cipher_suite=self.cipher_suite)
        self.tls_ctx.insert(self.server_hello)
        # Build method to generate EPMS automatically in TLSSessionCtx
        self.client_kex = tls.TLSRecord(version=self.version)/tls.TLSHandshake()/tls.TLSClientKeyExchange(data=self.tls_ctx.get_encrypted_pms())
        self.tls_ctx.insert(self.client_kex)

    def test_crypto_container_increments_sequence_number(self):
        client_seq_num = self.tls_ctx.crypto.session.key.client.seq_num
        server_seq_num = self.tls_ctx.crypto.session.key.server.seq_num
        tlsc.CryptoContainer(self.tls_ctx)
        client_seq_num += 1
        self.assertEqual(self.tls_ctx.crypto.session.key.client.seq_num, client_seq_num)
        self.assertEqual(self.tls_ctx.crypto.session.key.server.seq_num, server_seq_num)
        self.tls_ctx.client = False
        tlsc.CryptoContainer(self.tls_ctx)
        self.assertEqual(self.tls_ctx.crypto.session.key.client.seq_num, client_seq_num)
        self.assertEqual(self.tls_ctx.crypto.session.key.server.seq_num, server_seq_num + 1)

    def test_crypto_container_str_returns_cipher_payload(self):
        data = b"abcde"
        crypto_container = tlsc.CryptoContainer(self.tls_ctx, data)
        padding = crypto_container.padding
        self.assertEqual("%s%s%s%s" % (data, crypto_container.mac, padding, chr(len(padding))), str(crypto_container))

    def test_cipher_payload_is_block_size_aligned(self):
        data = b"A"*1025
        crypto_container = tlsc.CryptoContainer(self.tls_ctx, data)
        self.assertTrue(len(crypto_container) % AES.block_size == 0)

    def test_crypto_container_returns_ciphertext(self):
        data = b"C"*102
        self.tls_ctx.client = False
        crypto_container = tlsc.CryptoContainer(self.tls_ctx, data)
        cleartext = str(crypto_container)
        ciphertext = crypto_container.encrypt()
        self.assertEqual(cleartext, self.tls_ctx.crypto.server.dec.decrypt(ciphertext))

    def test_generated_mac_can_be_overiden(self):
        data = b"C"*102
        self.tls_ctx.client = False
        crypto_container = tlsc.CryptoContainer(self.tls_ctx, data)
        initial_mac = crypto_container.mac
        crypto_container.hmac(data_len=1024)
        self.assertNotEqual(initial_mac, crypto_container.mac)

    def test_tls_1_1_and_above_has_a_random_explicit_iv_with_block_cipher(self):
        data = b"C"*102
        self._do_kex(tls.TLSVersion.TLS_1_1)
        crypto_container = tlsc.CryptoContainer(self.tls_ctx, data)
        self.assertNotEqual(crypto_container.explicit_iv, "")
        self.assertEqual(len(crypto_container.explicit_iv), AES.block_size)
        self.assertTrue(str(crypto_container).startswith(crypto_container.explicit_iv))

    def test_tls_1_0_and_below_has_no_explicit_iv(self):
        data = b"C"*102
        crypto_container = tlsc.CryptoContainer(self.tls_ctx, data)
        self.assertEqual(crypto_container.explicit_iv, "")
        self.assertTrue(str(crypto_container).startswith(data))

if __name__ == "__main__":
    unittest.main()
