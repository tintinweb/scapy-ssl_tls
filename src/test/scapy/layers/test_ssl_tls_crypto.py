import binascii
import unittest
import ssl_tls as tls
import ssl_tls_crypto as tlsc
from Crypto.Hash import HMAC, MD5, SHA
from Crypto.Cipher import AES, DES3

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

    def test_negotiated_cipher_is_used_in_context(self):
        # RSA_WITH_NULL_MD5
        cipher_suite = 0x1
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello(gmt_unix_time=123456, random_bytes="A"*24, cipher_suite=cipher_suite)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.params.negotiated.key_exchange, tlsc.TLSSecurityParameters.crypto_params[cipher_suite]["key_exchange"]["name"])
        self.assertEqual(tls_ctx.params.negotiated.mac, tlsc.TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["name"])

    def test_negotiated_compression_method_is_used_in_context(self):
        # DEFLATE
        compression_method = 0x1
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello(gmt_unix_time=123456, random_bytes="A"*24, compression_method=compression_method)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.insert(pkt)
        self.assertEqual(tls_ctx.params.negotiated.compression_algo, tlsc.TLSCompressionParameters.comp_params[compression_method]["name"])
        input_ = "some data" * 16
        self.assertEqual(tls_ctx.compression.method.decompress(tls_ctx.compression.method.compress(input_)), input_)

class TestTLSSecurityParameters(unittest.TestCase):

    def setUp(self):
        self.pre_master_secret = "\x03\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
        self.client_random = "a" * 32
        self.server_random = "z" * 32
        self.master_secret = binascii.unhexlify("43278712b1feba3622c5745f79908a77b6e801239fc19390240cc45a17517b6218dfcb3f370c97f15329251e7a20ffb0")
        unittest.TestCase.setUp(self)

    def test_unsupported_cipher_suite_throws_exception(self):
        with self.assertRaises(tlsc.UnsupportedCipherError):
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
