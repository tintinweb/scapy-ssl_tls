# -*- coding: utf-8 -*-

import unittest

import scapy_ssl_tls.ssl_tls_keystore as tlsk


class TestAsymKeyStore(unittest.TestCase):

    def test_when_rsa_keystore_is_initialized_then_name_is_set(self):
        rsa_keystore = tlsk.RSAKeystore(b"5678")
        self.assertEqual("RSA Keystore", rsa_keystore.name)
        self.assertEqual(None, rsa_keystore.private)
        self.assertEqual(b"5678", rsa_keystore.public)
        self.assertEqual(None, rsa_keystore.certificate)
