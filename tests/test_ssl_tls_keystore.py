# -*- coding: utf-8 -*-

import binascii
import unittest

from Cryptodome.PublicKey import RSA
import scapy_ssl_tls.ssl_tls_keystore as tlsk


class TestAsymKeyStore(unittest.TestCase):

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
        self.rsa = RSA.importKey(self.pem_priv_key)

    def test_when_rsa_keystore_is_initialized_then_name_is_set(self):
        rsa_keystore = tlsk.RSAKeystore(self.rsa.publickey(), self.rsa)
        self.assertEqual("RSA Keystore", rsa_keystore.name)
        self.assertEqual(self.rsa, rsa_keystore.private)
        self.assertEqual(self.rsa.publickey(), rsa_keystore.public)
        self.assertEqual(2048, rsa_keystore.size)
        self.assertEqual(None, rsa_keystore.certificate)


class TestTLSKeystoreTopLevelFunctions(unittest.TestCase):

    def test_when_ansi_string_is_malformed_then_exception_is_raised(self):
        x, y = int(binascii.hexlify("123"), 16), int(binascii.hexlify("456"), 16)
        with self.assertRaises(ValueError):
            tlsk.ansi_str_to_point("1234")
        with self.assertRaises(ValueError):
            tlsk.ansi_str_to_point("\x04123")
        self.assertEqual(tlsk.ansi_str_to_point("\x04123456"), (x, y))
