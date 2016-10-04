# -*- coding: utf-8 -*-

import unittest

import scapy_ssl_tls.ssl_tls_keystore as tlsk


class TestAsymKeyStore(unittest.TestCase):

    def test_when_rsa_keystore_is_initialized_then_name_is_set(self):
        rsa_keystore = tlsk.RSAKeystore(b"5678")
        self.assertEqual(rsa_keystore.name, "RSA")
        self.assertEqual(rsa_keystore.private, None)
        self.assertEqual(rsa_keystore.public, b"5678")
        self.assertEqual(rsa_keystore.certificate, None)
