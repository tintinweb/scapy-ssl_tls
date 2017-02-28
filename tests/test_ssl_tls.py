#! -*- coding: utf-8 -*-

import binascii
import os
import re
import unittest
import scapy_ssl_tls.ssl_tls as tls
import scapy_ssl_tls.ssl_tls_crypto as tlsc
import scapy_ssl_tls.ssl_tls_keystore as tlsk

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import MD5, SHA
from Cryptodome.PublicKey import RSA
from scapy.all import rdpcap, Raw
from scapy.layers import x509


def env_local_file(file):
    return os.path.join(os.path.dirname(__file__), 'files', file)


class TestSSLv2Record(unittest.TestCase):
    def setUp(self):
        self.client_hello = tls.SSLv2Record(length=1234)/tls.SSLv2ClientHello(challenge="12345")/"TEST"
        self.client_hello_serialized_expected = '\x84\xd2\x01\x00\x02\x00\x00\x00\x00\x00\x0512345TEST'
        # this is: http://www.pcapr.net/view/mu/ssl-v2-2.pcap.html
        self.real_client_hello = '\x801\x01\x00\x02\x00\x18\x00\x00\x00\x10\x07\x00\xc0\x05\x00\x80\x03\x00\x80\x01\x00\x80\x08\x00\x80\x06\x00@\x04\x00\x80\x02\x00\x80vdu-\xa7\x98\xfe\xc9\x12\x92\xc1/4\x84 \xc5'

    def test_sslv2_de_serialize(self):
        pkt_serialized = str(tls.SSL(records=self.client_hello))
        self.assertEqual(pkt_serialized, self.client_hello_serialized_expected)
        pkt = tls.SSL(pkt_serialized)
        self.assertTrue(pkt.haslayer(tls.SSL))
        self.assertTrue(pkt.haslayer(tls.SSLv2Record))
        self.assertTrue(pkt.haslayer(Raw))
        self.assertEqual(pkt[tls.SSLv2Record].length, 1234)
        self.assertEqual(pkt[tls.SSLv2ClientHello].challenge, "12345")
        self.assertEqual(pkt[Raw].load, "TEST")

    def test_sslv2_real_client_hello(self):
        pkt = tls.SSL(self.real_client_hello)
        self.assertTrue(pkt.haslayer(tls.SSL))
        self.assertTrue(pkt.haslayer(tls.SSLv2Record))
        self.assertEqual(pkt[tls.SSLv2Record].length, 0x31)
        self.assertEqual(pkt[tls.SSLv2ClientHello].version, tls.TLSVersion.SSL_2_0)
        self.assertEqual(pkt[tls.SSLv2ClientHello].challenge, 'vdu-\xa7\x98\xfe\xc9\x12\x92\xc1/4\x84 \xc5')
        self.assertEqual(pkt[tls.SSLv2ClientHello].challenge_length, len('vdu-\xa7\x98\xfe\xc9\x12\x92\xc1/4\x84 \xc5'))
        self.assertEqual(pkt[tls.SSLv2ClientHello].cipher_suites_length, 0x18)
        self.assertEqual(pkt[tls.SSLv2ClientHello].cipher_suites, [0x700c0, 0x50080, 0x30080, 0x10080, 0x80080, 0x60040, 0x40080, 0x20080])
        self.assertEqual(len(pkt[tls.SSLv2ClientHello].cipher_suites), 8)
        self.assertEqual(pkt[tls.SSLv2ClientHello].session_id, '')
        self.assertEqual(pkt[tls.SSLv2ClientHello].session_id_length, 0x0)


class TestTLSRecord(unittest.TestCase):

    def setUp(self):
        self.server_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello()])
        self.cert_list = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSCertificateList()])
        self.server_hello_done = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHelloDone()])
        self.stacked_pkt = tls.TLS.from_records([self.server_hello, self.cert_list, self.server_hello_done])
        # issue 28
        der_cert = '0\x82\x03\xe70\x82\x02\xcf\xa0\x03\x02\x01\x02\x02\t\x00\xb9\xee\xd4\xd9U\xa5\x9e\xb30\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000p1\x0b0\t\x06\x03U\x04\x06\x13\x02UK1\x160\x14\x06\x03U\x04\n\x0c\rOpenSSL Group1"0 \x06\x03U\x04\x0b\x0c\x19FOR TESTING PURPOSES ONLY1%0#\x06\x03U\x04\x03\x0c\x1cOpenSSL Test Intermediate CA0\x1e\x17\r111208140148Z\x17\r211016140148Z0d1\x0b0\t\x06\x03U\x04\x06\x13\x02UK1\x160\x14\x06\x03U\x04\n\x0c\rOpenSSL Group1"0 \x06\x03U\x04\x0b\x0c\x19FOR TESTING PURPOSES ONLY1\x190\x17\x06\x03U\x04\x03\x0c\x10Test Server Cert0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xf3\x84\xf3\x926\xdc\xb2F\xcafz\xe5)\xc5\xf3I("\xd3\xb9\xfe\xe0\xde\xe48\xce\xee"\x1c\xe9\x91;\x94\xd0r/\x87\x85YKf\xb1\xc5\xf5z\x85]\xc2\x0f\xd3.)X6\xccHk\xa2\xa2\xb5&\xceg\xe2G\xb6\xdfI\xd2?\xfa\xa2\x10\xb7\xc2\x97D~\x874mm\xf2\x8b\xb4U+\xd6!\xdeSK\x90\xea\xfd\xea\xf985+\xf4\xe6\x9a\x0e\xf6\xbb\x12\xab\x87!\xc3/\xbc\xf4\x06\xb8\x8f\x8e\x10\x07\'\x95\xe5B\xcb\xd1\xd5\x10\x8c\x92\xac\xee\x0f\xdc#H\x89\xc9\xc6\x93\x0c"\x02\xe7t\xe7%\x00\xab\xf8\x0f\\\x10\xb5\x85;f\x94\xf0\xfbMW\x06U!"%\xdb\xf3\xaa\xa9`\xbfM\xaay\xd1\xab\x92H\xba\x19\x8e\x12\xech\xd9\xc6\xba\xdf\xecZ\x1c\xd8C\xfe\xe7R\xc9\xcf\x02\xd0\xc7\x7f\xc9~\xb0\x94\xe3SDX\x0b.\xfd)t\xb5\x06\x9b\\D\x8d\xfb2u\xa4:\xa8g{\x872\nP\x8d\xe1\xa2\x13J%\xaf\xe6\x1c\xb1%\xbf\xb4\x99\xa2S\xd3\xa2\x02\xbf\x11\x02\x03\x01\x00\x01\xa3\x81\x8f0\x81\x8c0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xe00,\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x1f\x16\x1dOpenSSL Generated Certificate0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x82\xbc\xcf\x00\x00\x13\xd1\xf79%\x9a\'\xe7\xaf\xd2\xef \x1bn\xac0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x146\xc3l\x88\xe7\x95\xfe\xb0\xbd\xec\xce>=\x86\xab!\x81\x87\xda\xda0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\xa9\xbdMW@t\xfe\x96\xe9+\xd6x\xfd\xb3c\xcc\xf4\x0bM\x12\xcaZt\x8d\x9b\xf2a\xe6\xfd\x06\x11C\x84\xfc\x17\xa0\xeccc6\xb9\x9e6j\xb1\x02Zj[?j\xa1\xea\x05e\xac~@\x1aHe\x88\xd19M\xd3Kw\xe9\xc8\xbb+\x9eZ\xf4\x0849G\xb9\x02\x081\x9a\xf1\xd9\x17\xc5\xe9\xa6\xa5\x96Km@\xa9[e(\xcb\xcb\x00\x03\x82c7\xd3\xad\xb1\x96;v\xf5\x17\x16\x02{\xbdSSFr4\xd6\x08d\x9d\xbbC\xfbd\xb1I\x07w\tazB\x17\x110\x0c\xd9\'\\\xf5q\xb6\xf0\x180\xf3~\xf1\x85?2~J\xaf\xb3\x10\xf7l\xc6\x85K-\'\xad\n \\\xfb\x8d\x19p4\xb9u_|\x87\xd5\xc3\xec\x93\x13A\xfcs\x03\xb9\x8d\x1a\xfe\xf7&\x86I\x03\xa9\xc5\x82?\x80\r)I\xb1\x8f\xed$\x1b\xfe\xcfX\x90F\xe7\xa8\x87\xd4\x1ey\xef\x99m\x18\x9f>\x8b\x82\x07\xc1C\xc7\xe0%\xb6\xf1\xd3\x00\xd7@\xabK\x7f+z>\xa6\x99LT'
        stacked_handshake_layers = tls.TLSRecord() / tls.TLSHandshakes(handshakes=
                                                                       [tls.TLSHandshake() / tls.TLSServerHello(),
                                                                        tls.TLSHandshake() / tls.TLSCertificateList() / tls.TLS10Certificate(
                                                                            certificates=[tls.TLSCertificate(data=x509.X509Cert(der_cert))]),
                                                                        tls.TLSHandshake() / tls.TLSServerHelloDone()])
        self.stacked_handshake = tls.TLS(str(stacked_handshake_layers))
            # str(tls.TLSRecord(content_type="handshake") / "".join(list(map(str, stacked_handshake_layers)))))
        self.empty_tls_handshake_serialized_expected = '\x16\x03\x01\x00\x04\x01\x00\x00\x00'
        unittest.TestCase.setUp(self)

    def test_pkt_tls_de_serialize(self):
        pkt = tls.SSL(self.empty_tls_handshake_serialized_expected)
        self.assertIn(tls.TLSRecord, pkt)
        self.assertIn(tls.TLSHandshake, pkt)
        pkt[tls.TLSHandshake].type == tls.TLSHandshakeType.CLIENT_HELLO
        pkt[tls.TLSHandshake].length == 0
        pkt[tls.TLSRecord].content_type == tls.TLSContentType.HANDSHAKE
        pkt[tls.TLSRecord].version == tls.TLSVersion.TLS_1_0
        pkt[tls.TLSRecord].length == 0x04

    def test_empty_handshake_serializes_to_known_data(self):
        self.assertEqual(str(tls.TLSRecord() / tls.TLSHandshakes(handshakes=tls.TLSHandshake())), self.empty_tls_handshake_serialized_expected)

    def test_pkt_built_from_stacked_tls_records_is_identical(self):
        self.assertEqual(len(str(self.server_hello)), len(str(self.stacked_pkt.records[0])))
        self.assertEqual(len(str(self.cert_list)), len(str(self.stacked_pkt.records[1])))
        self.assertEqual(len(str(self.server_hello_done)), len(str(self.stacked_pkt.records[2])))
        self.assertEqual(len(str(self.server_hello)) - len(tls.TLSRecord()),
                         self.stacked_pkt.records[0][tls.TLSRecord].length)
        self.assertEqual(len(str(self.cert_list)) - len(tls.TLSRecord()),
                         self.stacked_pkt.records[1][tls.TLSRecord].length)
        self.assertEqual(len(str(self.server_hello_done)) - len(tls.TLSRecord()),
                         self.stacked_pkt.records[2][tls.TLSRecord].length)

    def test_pkt_built_from_stacked_tls_handshakes_is_identical(self):
        # issue #28
        # layers are present
        self.assertTrue(self.stacked_handshake.haslayer(tls.TLSRecord))
        self.assertTrue(self.stacked_handshake.haslayer(tls.TLSHandshake))
        self.assertTrue(self.stacked_handshake.haslayer(tls.TLSServerHello))
        self.assertTrue(self.stacked_handshake.haslayer(tls.TLSCertificateList))
        self.assertTrue(self.stacked_handshake.haslayer(tls.TLSCertificate))
        # Note (tin): scapy only dissects as long as there are bytes left to be passed to sublayers.
        #             since TLSServerHelloDone() is a zero-length layer, dissection already stops
        #             at the TLSHandshake layer. As a consequence the dissection stream is not
        #             going to have a TLSServerHelloDone() layer but the ServerHelloDone hint
        #             set in the TLSHandhsake.type property.
        # self.assertTrue(self.stacked_handshake.haslayer(tls.TLSServerHelloDone))
        # check last handshake layer type
        self.assertEquals(self.stacked_handshake[tls.TLSHandshakes].handshakes[2].type, tls.TLSHandshakeType.SERVER_HELLO_DONE)
        # check TLS layers one by one
        self.assertEqual(re.findall(r'<(TLS[\w]+)', str(repr(self.stacked_handshake))),
                         ['TLSRecord', 'TLSHandshakes', 'TLSHandshake', 'TLSServerHello',
                          'TLSHandshake', 'TLSCertificateList', 'TLS10Certificate', 'TLSCertificate',
                          'TLSHandshake'])

    def test_fragmentation_fails_on_non_aligned_boundary_for_handshakes(self):
        # from scapy.all import *
        # bind_layers(tls.TLSRecord, tls.TLSHandshake, {'content_type': tls.TLSContentType.HANDSHAKE})
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello()])
        # pkt = tls.TLSRecord(content_type=tls.TLSContentType.HANDSHAKE) / ("S"*33)
        fragments = pkt.fragment(7)
        self.assertIsInstance(fragments, tls.TLS)
        self.assertEqual(len(fragments.records), len(str(pkt)) / 7)
        self.assertEqual(fragments.records[0].length, 7)

    def test_fragmenting_a_record_returns_a_list_of_records_when_fragment_size_is_smaller_than_record(self):
        frag_size = 3
        app_data = "A" * 7
        pkt = tls.TLSRecord(version=tls.TLSVersion.TLS_1_1, content_type=tls.TLSContentType.APPLICATION_DATA) / app_data
        fragments = pkt.fragment(frag_size)
        self.assertEqual(len(fragments.records), len(app_data) / frag_size + len(app_data) % frag_size)
        record_length = len(tls.TLSRecord())
        self.assertTrue(all(list(map(lambda x: x.haslayer(tls.TLSRecord), fragments.records))))
        self.assertEqual(len(fragments.records[0]), record_length + frag_size)
        self.assertEqual(len(fragments.records[1]), record_length + frag_size)
        self.assertEqual(len(fragments.records[2]), record_length + (len(app_data) % frag_size))

    def test_fragmenting_a_record_does_nothing_when_fragment_size_is_larger_than_record(self):
        app_data = "A" * 7
        frag_size = len(app_data)
        pkt = tls.TLSRecord(version=tls.TLSVersion.TLS_1_1, content_type=tls.TLSContentType.APPLICATION_DATA) / app_data
        self.assertEqual(str(pkt), str(pkt.fragment(frag_size)))
        frag_size = len(app_data) * 2
        self.assertEqual(str(pkt), str(pkt.fragment(frag_size)))

    def test_large_record_payload_is_not_fragmented_when_smaller_then_max_ushort(self):
        app_data = "A" * tls.TLSRecord.MAX_LEN
        pkt = tls.TLSRecord(version=tls.TLSVersion.TLS_1_1, content_type=tls.TLSContentType.APPLICATION_DATA) / app_data
        try:
            str(pkt)
        except tls.TLSFragmentationError:
            self.fail()

    def test_large_record_payload_is_fragmented_when_above_max_ushort(self):
        app_data = "A" * (tls.TLSRecord.MAX_LEN + 1)
        pkt = tls.TLSRecord(version=tls.TLSVersion.TLS_1_1, content_type=tls.TLSContentType.APPLICATION_DATA) / app_data
        with self.assertRaises(tls.TLSFragmentationError):
            str(pkt)


class TestTLSDissector(unittest.TestCase):

    def setUp(self):
        self.payload = binascii.unhexlify(
            "160301004a02000046030155514d08929c06119d291bae09ec50ba48f52069c840673c76721aa5c53bc352202de1c20c707ba9b083282d2eba3d95bdfb5847eb9241f252173a04c9f990d508002f0016030104080b0004040004010003fe308203fa308202e2a003020102020900980ceed2480234b2300d06092a864886f70d0101050500305b310b3009060355040613025553311330110603550408130a43616c69666f726e696131173015060355040a130e4369747269782053797374656d73311e301c06035504031315616d73736c2e656e672e636974726974652e6e6574301e170d3135303432343233313435395a170d3235303432313233313435395a305b310b3009060355040613025553311330110603550408130a43616c69666f726e696131173015060355040a130e4369747269782053797374656d73311e301c06035504031315616d73736c2e656e672e636974726974652e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c0e2f8d4d4423ef7ce3e6ea789ad83c831fd679a8745bfe7d3628a544b7f04fec8bb8eb72737a6334764b68e796fbd70f19a1754776aba2f5d9685f2931b57456825ca75baca540c34de26115037d76d1a6fabbab6cd666af98fcb6b9c2fc714fd523828babae067f9ad7da51100306b4a5783a1402a4d80524dc14d0867f526e055dbd32e6f9f785072d72b8c36994bb56c2cdbf74e2149e7c625fed1c6405e205289c2b4608bd28704303764227f4540b95054c115be9185223b8a815462818090c6c933ce4c39d4049197106fe84918048adfd185fc7d64167804ccafbae8b84dc81d0288f4078c736a4ccc04c27184ffb45b14b4bd79ab472dba8877c20f0203010001a381c03081bd301d0603551d0e041604141979840d258e11dad71d942fe77e567fc0bbb48430818d0603551d2304818530818280141979840d258e11dad71d942fe77e567fc0bbb484a15fa45d305b310b3009060355040613025553311330110603550408130a43616c69666f726e696131173015060355040a130e4369747269782053797374656d73311e301c06035504031315616d73736c2e656e672e636974726974652e6e6574820900980ceed2480234b2300c0603551d13040530030101ff300d06092a864886f70d010105050003820101006fbd05d20b74d33b727fb2ccfebf3f36950278631bf87e77f503ce8e9a080925b6276f32218cadd0a43d40d89ba0e5fd9897ac536a079440385ba59e2593100df52224a8f8b786561466558d435d9ea5e4f320028ee7afa005f09b64b16f3e6b787af31b28d623edd480a50dd64fc6f0da0eab0c38c5d8965504c9c3d5c2c85514b7b1f8df9ee2d9116ac05781dbef26a66e98679f84b0378a1f8857f69e72cf72c11e836e0144153bd412dcfb506ed9e4a6181208b92be3ba9ec13f3c5b19eb700884e04a051603f2f2302d542e094afcce6694c5e46452a486b9ba339578e0f530f98824872eef62a23d685e9710c47362a034b699b7f9e1521b135e1e950d16030100040e000000")
        unittest.TestCase.setUp(self)

    def _static_tls_handshake(self):
        # Setup static parameters, so PRF output is reproducible
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.premaster_secret = "\x03\x01" + "C" * 46
        client_hello = tls.TLSRecord(
            version="TLS_1_0") / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(
            version="TLS_1_0",
            gmt_unix_time=1234,
            random_bytes="A" * 28,
            session_id="",
            compression_methods=[0],
            cipher_suites=(
                tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA))])
        tls_ctx.insert(client_hello)
        server_hello = binascii.unhexlify(
            "160301004a02000046030155662cd45fade845839a3c8dba0e46f1abcd2fd941f4e95e75ab6d61811abcf420960ccadc00abc7043cca458d9a1df1cb877a5005b53f754ac80d392990fae3c7002f00160301047c0b0004780004750004723082046e30820356a003020102020900d1e1f53a9203251a300d06092a864886f70d0101050500308180310b3009060355040613025553311330110603550408130a536f6d652d53746174653112301006035504071309536f6d652d6369747931153013060355040a130c536f6d652d636f6d70616e793110300e060355040b1307536f6d652d4f55311f301d06035504031316736f6d652d7365727665722e736f6d652e7768657265301e170d3135303532323139313631325a170d3235303531393139313631325a308180310b3009060355040613025553311330110603550408130a536f6d652d53746174653112301006035504071309536f6d652d6369747931153013060355040a130c536f6d652d636f6d70616e793110300e060355040b1307536f6d652d4f55311f301d06035504031316736f6d652d7365727665722e736f6d652e776865726530820122300d06092a864886f70d01010105000382010f003082010a0282010100cd7b7165ee7528f107cf666edc673eedc863544ebe8cc3741346015eea182a73a9e18e26f6f1553d83843d2bdacdd4501faec7b4f5446b8790053f152e23f70d121ca7f63a22a657536ee4b50b8777568ef469905ce05211178dd9ebe223b21246cce4baf351d0b81b464830e15fb7178cf5f39e7673de7779e5dbbd7a3d2ea98589b0d6003635447693ed2ec632c3dbb632ac254e3b8cd78e1ea160982627e2cd3a369c4bb43c486141b97fbbd9d3cb014b92e0ec6ecf46ded64749bbecfb6f98d0d2f459d5cf0054a6522280af961dfcbe1650937180f43decf2f8725b94eeec10248cdc70acad63bcc3cd5370d0dc0f3cba8d369909c6b917f243e5e5bc270203010001a381e83081e5301d0603551d0e041604143cc2f7fc85dbbe4b0566b35bde744484438ae83e3081b50603551d230481ad3081aa80143cc2f7fc85dbbe4b0566b35bde744484438ae83ea18186a48183308180310b3009060355040613025553311330110603550408130a536f6d652d53746174653112301006035504071309536f6d652d6369747931153013060355040a130c536f6d652d636f6d70616e793110300e060355040b1307536f6d652d4f55311f301d06035504031316736f6d652d7365727665722e736f6d652e7768657265820900d1e1f53a9203251a300c0603551d13040530030101ff300d06092a864886f70d0101050500038201010001738e2985692d8239fb1795e6ea0718755cf106cd739f7113afd3a074add07f981b06f34b9df3e1658c153355c5061b369d60d341eb4ccefdd98d6d6790be499cde8bd5705d1a8a89bb141599f3319914f8539e294848c106386218d8679da46ba90a2ce7587265cb55d6a629569b65581ee2e88ded264b81dff1c11e2c55728efe170dfe4f76706fbbda137b02e0fa987355b0cfdb3f8637e35473e4a6eccdcbc27d55d1f956a5f2c454e937df71d42e21d45d227477e26053b8be003fa527746b163b3d4b9a585d2860e5080ed9737d4c5fa5a32eee45a4e56d8a03542349619084580cc9c6c25b1ac7f3854b501423eafdd32896af92ce8ca6923947d77c16030100040e000000")
        tls_ctx.insert(tls.TLS(server_hello))
        return tls_ctx

    def test_stacked_tls_records_are_correctly_dissected_from_bytes(self):
        # This is tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHello()/tls.TLSRecord()/tls.TLSHandshake()/tls.TLSCertificateList()/tls.TLSRecord()/tls.TLSHandshake()/tls.TLSServerHelloDone()
        # Grabbed from the wire, with hardcoded parameters
        pkt = tls.TLS(self.payload).records
        self.assertEqual(pkt[0][tls.TLSRecord].length, 0x4a)
        self.assertEqual(pkt[0][tls.TLSHandshake].length, 0x46)
        self.assertEqual(pkt[0][tls.TLSHandshake].gmt_unix_time, 1431391496)
        self.assertEqual(pkt[0][tls.TLSHandshake].session_id,
                         binascii.unhexlify("2de1c20c707ba9b083282d2eba3d95bdfb5847eb9241f252173a04c9f990d508"))
        self.assertEqual(pkt[0][tls.TLSHandshake].cipher_suite, tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA)
        self.assertEqual(pkt[0][tls.TLSHandshake].compression_method, tls.TLSCompressionMethod.NULL)
        self.assertEqual(pkt[1].length, 0x408)
        self.assertEqual(pkt[1][tls.TLSHandshake].length, 0x404)
        self.assertEqual(pkt[1][tls.TLSCertificateList].length, 0x401)
        self.assertEqual(pkt[2][tls.TLSRecord].length, 0x4)
        self.assertEqual(pkt[2][tls.TLSHandshake].type, 0x0e)

    def test_dissected_stacked_tls_records_are_identical_to_input_packet(self):
        pkt = tls.TLS(self.payload)
        self.assertEqual(len(pkt), len(self.payload))
        self.assertEqual(str(pkt), self.payload)

    def test_extensions_are_removed_when_non_specified(self):
        pkt = tls.TLS(self.payload)
        self.assertListEqual(pkt[tls.TLSServerHello].extensions, [])
        self.assertIsNone(pkt[tls.TLSServerHello].extensions_length)

    def test_encrypted_layer_is_decrypted_if_required(self):
        tls_ctx = self._static_tls_handshake()
        client_kex = tls.TLS.from_records(
            [tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() / tls_ctx.get_encrypted_pms()]),
             tls.TLSRecord() / tls.TLSChangeCipherSpec()], tls_ctx)
        tls_ctx.insert(client_kex)
        tls_ctx.insert(tls.to_raw(tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSFinished(data=tls_ctx.get_verify_data())]), tls_ctx))
        server_finished = binascii.unhexlify(
            "14030100010116030100305b0241932c63c0cf1e4955e0cc65f751a3921fe8227c2bae045c66be327f7e68a39dc163b382c90d2caaf197ba0563a7")
        server_finished_records = tls.TLS(server_finished, ctx=tls_ctx)
        tls_ctx.insert(server_finished_records)
        app_request = tls.to_raw(tls.TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_ctx)
        tls_ctx.insert(app_request)
        app_response = binascii.unhexlify(
            "1703010020d691f8104d8fd877e7a7a7f3729936a92272c6fa93999f37a3a4b2355454a26617030107e04c7017bec4bb802bf713f815f692a50d1d911d8d78d8edc14b0e2dfde876b3da4ce748a0c6c1917490f73ba5d04fe61d250f5478416987904aa45461bc64848c3bdc573e6c99338634d9f374cba9b847b06e1f8c56039bda3b1fd5bf0007372472fa45333ccd907cec08d2e1d1beb6e1bbf7f155e09e71e480a32104873c60162d873fb0310d91261b120f51f5a7b75084d6c4bb6ba11ba59334343c96ad849e39ff09e356dcc34ef7b9857112b6a3530b85c17ac2093439e980cc1d3a78d5708ed0aea96e74fdeed11e1a2dd5dbce67f85554706a32b5b98a3a7f0752dcfe30dd1726f28d37d7eea7282efc3db3273e93cb30cec75bd200128372488b74213360ec885e720e8876cdd4a6ff0e4cd34e8726b3ce6e04e1462981f2d5acf00a4b9a478f1a6d39b3c66884364ee7b2c5294380ca140aa41d99af4b809abba5a613e690782b3ea1b09fe0daaadc32a2ca2023e19d07fa1f68d2e1268a4be72f1695676285567111cbfd89360a92227f1b7f3c2cbc92f329f02aee9b45868a11517419e7d70da2ca4709d174b5014e7d823e24d3e29ee8c62dbe7c2f1a631a5aa2571e5c5f23f2c7d78997c41eeabc91f413c90806736438c8d34f8114dfe595a0e22febab37fe04ad2966416ad0c307426dd9d3627b0642be021c5703ec40279115d11415e59dd86102ca018e8a4aed7c1988c8e53a36699fa8e55f903489bbcc9d281bd3822a927ac1536695c9419d87c30653c60b7f4b65647e4b1900b6b3963b5fc981bea5d131f1f92d81570f3dfd52287d6e7171107f2bda5f219eb2cb43d965b46ed425624b527d9c2a8ec0391144c7e9a67fead45d3cc7f0fbaeae21dd0297ecd00eea103675cf843ee7c545c611d41776adc90ddf6a4d4ff0c8fc8899b3eb76c79dbcac0d9f9b6c0e8a334a8bddff6f4f90b5b4004619bc50b65b309048c9b68d610033f2eb73dd2061e418826892494eff8df1adf5dc1b6968f620645c765507b49d48d734dd618c1dac32f28ab99f6dab2e401a8bbf8c19abf1181f8c1b98c7c06179fa096cbba3610710539b50c8f6c39fa92fe50635497dea7a4359a8dc1987ec329b3e06076ee2fa3e55fcc41f01c4c953587f60a14645850bf77675a78c6ac2cdb8a0bcf2eaf7a8f0ec154a6dc75f5c53c8ce8c733ad236b4d635fa49b6210b24a9d18326dcdac12bfff5551636306bdbbbe4190530e5a0704e9fb8f30ef7b1730686eb395c3d11c966caaeb14ee4138e8bcfe8f73119a0fab734eed3443944c6d8800124b6eeed36d530dcafa71d91657d97069b1604e7922094604aacecbf42cd487b15e2de25819fd4179ca615404307127640aa80eb8283e5462fe1abd5f9ebab03f6e95ba2bf2e8ba3e96170aed26565cde86777367e4b2193dfaceb350e1371394109e1f408c994f3c7dcc5eae506263834618a727c919f6e76898214c931f8d0d1b0200fb14a7d46e78d8634cbd918cc560e58cf2516498ecc55af46471ae01ba385727e262afe16510d54516d0c011ce678271f14a007d4c7f314cd5ae51ada413e315f85e3990b1686a8c3f9c06fe0d63e6c3438aa5b31ab526989d1f3577139eed35afdafdeb968fd88f15a670523db921a82428fac13a3cf67584e3bca1d3e7ac52ea6cf8a49992fceab78b837ed1d26cf3ce3aab33c85ac392e0e4baff9b63777f9339bfb8821759c8b4632e4ff41569fd5dda7cdadb44f1efc1dd5e19f76bff4bc9ea3b65dd0ba35cad76de5f075cb2a969a79b24c73ce8c40a2c72eb39c321404f784bd30c09073be67ed7fddcb5e1cecf78258d1b7d75dbc575c693ee045a44e09b020ca11fd62b72c5d5d5a0aa81936db25c400615c6a802bb3d218ec4cf135f27c288ba34db438902073b55e1dcd3afcef4d608d0ba63c1aecec0ea851de52931a6ccb3054a1f37a6cc2d62342226ea5249583aadd87f3bf308f5355d4d349772b14a6dba9076fa8a32cdc72cc2ee8c59bbdf2980192e8de69694d49cb81eb3e32770c477035130593c29288a10d67e0a261352c1d60c1565180c41c4ee7f3e07d4a5fb6f4d6c5ef087741ce6078ed8fecb1cf2894efb0b72d62119934831aab0d93ce7609b1d7b2e3d2b0fc0099e2ef70cd56a8cad09a4407ec34090d138b30adc2b872e286ddd22102ad8149fdb4b69266ba476aad1cc27fa4ca7170f2ac1e36c3800c6109e3e59007a681a2f22f836c1e75d86df4760959475a55e360503481adac9ad89b2f183f3366f8f71436a8717eb8b40ceb1b57e247b6aa79d88372fc45cfec9d26de12b4eb71bd2b322ccb49131b799ef5bfc240c2c6b0c4de812a0458865e85ea4b3738a164b845c82084dee165d0cfe88e96570f7f0eff3acbbcaeede932e2c3329349eae0e6f5b2eac5fe137f7a4ee5896b9dfa3f22e6b7f02868e3ca45be16f6df6f164e43ea4b57d1c2d9929336b0cc1c1267c0828d0e22b22481ab2a2a34824c2cd4408e663d16cf1111f13ddae650c5859da944f18892ff75997dd245c6e728670a5afd485002560b6e2e79cd43d08dbd31994ccbc6b0b222aaa415583cd2f3d12025db6c8bba2eeea56f9b806760c58eead3f71477987019c75d409e0ff1f99a0cb8910c818173823ab0f53f2f94bc8b054fc0bfd5f95e328c0d73fe4e2b9383be452c14d9d6882e371cd76e375d44aecb2e134cd86fdbaa367554f996b7918b4d32f83824a2486a2dafa83e5c0de439253083823311d07963ffb7b17edaa490acd07488868bf4a03eea544787d0eeae87c2079a2c4b0b860717637938660d6cbc4cf65f3e9f8b0eeb09ba8b2fab43fd074da31cc0c13692ea72f377aec89a77babb545b6da2f09a32")
        app_response_records = tls.TLS(app_response, ctx=tls_ctx)
        tls_ctx.insert(app_response_records)
        # Test decryption against given states
        self.assertTrue(server_finished_records.haslayer(tls.TLSHandshakes))
        self.assertTrue(server_finished_records.haslayer(tls.TLSFinished))
        self.assertEqual(server_finished_records[tls.TLSHandshakes].padding_len, ord("\x0b"))
        self.assertEqual(server_finished_records[tls.TLSHandshakes].padding,
                         "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")
        self.assertEqual(server_finished_records[tls.TLSHandshakes].mac,
                         "\xac'\x9a\x94\xf6t'\x18E\x03nD\x0b\xf4\xf7\xf5T\xce\x05q")
        self.assertEqual(server_finished_records[tls.TLSFinished].data, "3\x13V\xac\x90.6\x89~7\x13\xbd")
        self.assertTrue(app_response_records.haslayer(tls.TLSPlaintext))
        self.assertTrue(app_response_records[3][tls.TLSPlaintext].data.startswith("HTTP"))

    def test_cleartext_alert_is_not_decrypted_with_block_cipher(self):
        tls_ctx = self._static_tls_handshake()
        alert = tls.TLSRecord() / tls.TLSAlert(level=tls.TLSAlertLevel.FATAL,
                                               description=tls.TLSAlertDescription.HANDSHAKE_FAILURE)
        record = tls.TLS(str(alert), ctx=tls_ctx)
        self.assertTrue(record.haslayer(tls.TLSAlert))
        self.assertEqual(record[tls.TLSAlert].level, tls.TLSAlertLevel.FATAL)
        self.assertEqual(record[tls.TLSAlert].description, tls.TLSAlertDescription.HANDSHAKE_FAILURE)

    def test_cleartext_handshake_is_not_decrypted(self):
        tls_ctx = self._static_tls_handshake()
        handshake = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerKeyExchange() / tls.TLSServerDHParams()])
        record = tls.TLS(str(handshake), ctx=tls_ctx)
        self.assertTrue(record.haslayer(tls.TLSServerKeyExchange))

    def test_encrypted_handshake_which_fails_decryption_throws_error(self):
        tls_ctx = self._static_tls_handshake()
        client_kex = tls.TLS.from_records(
            [tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() / tls_ctx.get_encrypted_pms()]),
             tls.TLSRecord() / tls.TLSChangeCipherSpec()], tls_ctx)
        tls_ctx.insert(client_kex)
        tls_ctx.insert(tls.to_raw(tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSFinished(data=tls_ctx.get_verify_data())]), tls_ctx))
        record = tls.TLSRecord() / ("C" * 5)
        with self.assertRaises(tls.TLSProtocolError):
            tls.TLS(str(record), ctx=tls_ctx)


class TestTLSDecryptablePacket(unittest.TestCase):

    def test_packet_does_not_contain_mac_or_padding_if_not_received_encrypted(self):
        pkt = tls.TLSRecord() / tls.TLSChangeCipherSpec()
        records = tls.TLS(str(pkt))
        with self.assertRaises(AttributeError):
            records[tls.TLSChangeCipherSpec].mac
            records[tls.TLSChangeCipherSpec].padding

    def test_tls_1_1_packet_does_not_contain_mac_or_padding_if_not_received_encrypted(self):
        pkt = tls.TLSRecord(version=tls.TLSVersion.TLS_1_1) / tls.TLSChangeCipherSpec()
        records = tls.TLS(str(pkt))
        with self.assertRaises(AttributeError):
            records[tls.TLSChangeCipherSpec].explicit_iv
            records[tls.TLSChangeCipherSpec].mac
            records[tls.TLSChangeCipherSpec].padding

    def test_session_context_is_removed_from_scapy_on_init(self):
        pkt = tls.TLSRecord() / tls.TLSAlert()
        records = tls.TLS(str(pkt), ctx=tlsc.TLSSessionCtx())
        with self.assertRaises(KeyError):
            records.fields["ctx"]

    def test_streaming_mac_and_padding_are_added_if_session_context_is_provided(self):
        data = "%s%s" % ("A" * 2, "B" * MD5.digest_size)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(
            tlsc.TLSPRF(tls.TLSVersion.TLS_1_0), tls.TLSCipherSuite.RSA_EXPORT1024_WITH_RC4_56_MD5, "A" * 48, "B" * 32,
            "C" * 32)
        records = tls.TLSAlert(data, ctx=tls_ctx)
        self.assertEqual("B" * MD5.digest_size, records[tls.TLSAlert].mac)
        self.assertEqual("", records[tls.TLSAlert].padding)

    def test_cbc_mac_and_padding_are_added_if_session_context_is_provided(self):
        data = "%s%s%s" % ("A" * 2, "B" * SHA.digest_size, "\x03" * 4)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(
            tlsc.TLSPRF(tls.TLSVersion.TLS_1_0), tls.TLSCipherSuite.RSA_WITH_DES_CBC_SHA, "A" * 48, "B" * 32, "C" * 32)
        records = tls.TLSAlert(data, ctx=tls_ctx)
        self.assertEqual(ord("\x03"), records[tls.TLSAlert].padding_len)
        self.assertEqual("\x03" * 3, records[tls.TLSAlert].padding)
        self.assertEqual("B" * SHA.digest_size, records[tls.TLSAlert].mac)

    def test_explicit_iv_is_added_for_tls_1_1_if_session_context_is_provided(self):
        data = "%s%s%s%s" % ("C" * AES.block_size, "A" * 2, "B" * SHA.digest_size, "\x03" * 4)
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.version = tls.TLSVersion.TLS_1_1
        tls_ctx.requires_iv = True
        tls_ctx.sec_params = tlsc.TLSSecurityParameters.from_pre_master_secret(
            tlsc.TLSPRF(tls.TLSVersion.TLS_1_0), tls.TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA, "A" * 48, "B" * 32,
            "C" * 32)
        records = tls.TLSAlert(data, ctx=tls_ctx)
        self.assertEqual(ord("\x03"), records[tls.TLSAlert].padding_len)
        self.assertEqual("\x03" * 3, records[tls.TLSAlert].padding)
        self.assertEqual("B" * SHA.digest_size, records[tls.TLSAlert].mac)
        self.assertEqual("C" * AES.block_size, records[tls.TLSAlert].explicit_iv)


class TestTLSClientHello(unittest.TestCase):

    def setUp(self):
        self.pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[
            tls.TLSHandshake() / \
            tls.TLSClientHello(extensions=[
                tls.TLSExtension() /
                tls.TLSExtServerNameIndication(server_names=[tls.TLSServerName(data="www.github.com"),
                                                             tls.TLSServerName(data="github.com")]),
                tls.TLSExtension() /
                tls.TLSExtALPN(protocol_name_list=[tls.TLSALPNProtocol(data="http/1.1"),
                                                   tls.TLSALPNProtocol(data="http/1.0")]),
                tls.TLSExtension() /
                tls.TLSExtALPN(protocol_name_list=[tls.TLSALPNProtocol(data="http/2.0"), ]),
                tls.TLSExtension() /
                tls.TLSExtMaxFragmentLength(fragment_length=0x03),
                tls.TLSExtension() /
                tls.TLSExtCertificateURL(
                    certificate_urls=[tls.TLSURLAndOptionalHash(url="http://www.github.com/tintinweb")]),
                tls.TLSExtension() /
                tls.TLSExtECPointsFormat(ec_point_formats=[tls.TLSEcPointFormat.ANSIX962_COMPRESSED_CHAR2]),
                tls.TLSExtension() /
                tls.TLSExtEllipticCurves(named_group_list=[tls.TLSSupportedGroup.SECT571R1, ]),
                tls.TLSExtension() /
                tls.TLSExtHeartbeat(mode=tls.TLSHeartbeatMode.PEER_NOT_ALLOWED_TO_SEND),
                tls.TLSExtension() /
                tls.TLSExtSessionTicketTLS(data="myticket"),
                tls.TLSExtension() /
                tls.TLSExtRenegotiationInfo(data="myreneginfo"),
            ], )])
        unittest.TestCase.setUp(self)

    def test_dissect_contains_client_hello(self):
        p = tls.SSL(str(self.pkt))
        self.assertEqual(len(p.records), 1)
        record = p.records[0]
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshake))
        self.assertTrue(record.haslayer(tls.TLSClientHello))

    def test_dissect_stacked_contains_multiple_client_hello(self):
        records = 5
        p = tls.SSL(str(self.pkt) * records)
        self.assertEqual(len(p.records), records)
        for record in p.records:
            self.assertTrue(record.haslayer(tls.TLSRecord))
            self.assertTrue(record.haslayer(tls.TLSHandshake))
            self.assertTrue(record.haslayer(tls.TLSClientHello))

    def test_dissect_client_hello(self):
        p = tls.SSL(str(self.pkt))
        record = p.records[0]
        self.assertEqual(record[tls.TLSRecord].version, self.pkt[tls.TLSRecord].version)
        self.assertEqual(record[tls.TLSHandshake].type, self.pkt[tls.TLSHandshake].type)
        self.assertEqual(record[tls.TLSClientHello].version, self.pkt[tls.TLSClientHello].version)
        self.assertEqual(record[tls.TLSClientHello].gmt_unix_time, self.pkt[tls.TLSClientHello].gmt_unix_time)
        self.assertEqual(record[tls.TLSClientHello].random_bytes, self.pkt[tls.TLSClientHello].random_bytes)
        self.assertEqual(record[tls.TLSClientHello].session_id, self.pkt[tls.TLSClientHello].session_id)
        self.assertEqual(record[tls.TLSClientHello].cipher_suites, self.pkt[tls.TLSClientHello].cipher_suites)
        self.assertEqual(record[tls.TLSClientHello].compression_methods,
                         self.pkt[tls.TLSClientHello].compression_methods)

    def test_dissect_client_hello_extensions(self):
        p = tls.SSL(str(self.pkt))
        record = p.records[0]
        extensions = record[tls.TLSClientHello].extensions
        self.assertEquals(extensions.pop()[tls.TLSExtRenegotiationInfo].data, "myreneginfo")
        self.assertEquals(extensions.pop()[tls.TLSExtSessionTicketTLS].data, "myticket")
        self.assertEquals(extensions.pop()[tls.TLSExtHeartbeat].mode, tls.TLSHeartbeatMode.PEER_NOT_ALLOWED_TO_SEND)
        self.assertEquals(extensions.pop()[tls.TLSExtSupportedGroups].named_group_list[0], tls.TLSSupportedGroup.SECT571R1)
        self.assertEquals(extensions.pop()[tls.TLSExtECPointsFormat].ec_point_formats[0],
                          tls.TLSEcPointFormat.ANSIX962_COMPRESSED_CHAR2)
        self.assertEquals(extensions.pop()[tls.TLSExtCertificateURL].certificate_urls[0].url,
                          "http://www.github.com/tintinweb")
        self.assertEquals(extensions.pop()[tls.TLSExtMaxFragmentLength].fragment_length, 0x03)
        self.assertEquals(extensions.pop()[tls.TLSExtALPN].protocol_name_list[0].data, "http/2.0")
        ext = extensions.pop()
        self.assertEquals(ext[tls.TLSExtALPN].protocol_name_list[1].data, "http/1.0")
        self.assertEquals(ext[tls.TLSExtALPN].protocol_name_list[0].data, "http/1.1")
        ext = extensions.pop()
        self.assertEquals(ext[tls.TLSExtServerNameIndication].server_names[1].data, "github.com")
        self.assertEquals(ext[tls.TLSExtServerNameIndication].server_names[0].data, "www.github.com")

    def test_dissect_client_hello_conditional_extensions_length(self):
        hello = tls.SSL(str(self.pkt))[tls.TLSClientHello]
        self.assertTrue("extensions_length=" in repr(hello))
        self.assertEqual(hello.extensions_length, len(''.join(str(e) for e in hello.extensions)))


class TestTLSServerHello(unittest.TestCase):
    def test_when_using_tls13_then_fields_are_removed(self):
        server_hello = tls.TLSServerHello(version=tls.TLSVersion.TLS_1_3)
        server_hello = tls.TLSServerHello(str(server_hello))
        self.assertEqual(server_hello.version, tls.TLSVersion.TLS_1_3)
        self.assertIsNone(server_hello.session_id_length)
        self.assertIsNone(server_hello.session_id)
        # No clue why scapy raises AttributeError somtimes and returns None sometimes
        # For ConditionalField
        with self.assertRaises(AttributeError):
            server_hello.compression_methods_length
        with self.assertRaises(AttributeError):
            server_hello.compression_methods
        self.assertIsNone(server_hello.gmt_unix_time)
        self.assertIsNone(server_hello.random_bytes)
        self.assertNotEqual(server_hello.random, "")
        self.assertEqual(len(server_hello.random), 32)


class TestKeyExchange(unittest.TestCase):
    def test_when_server_key_exchange_is_dh_then_it_is_dissected_correctly(self):
        record = tls.TLSRecord() / tls. TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(),
                                                                  tls.TLSHandshake() / tls.TLSServerKeyExchange() /
                                                                  tls.TLSServerDHParams(p="1234", g="2", y_s="5", sig="456")])
        self.assertTrue(record.haslayer(tls.TLSServerDHParams))
        record = tls.TLSRecord(str(record))
        self.assertTrue(record.haslayer(tls.TLSServerDHParams))
        self.assertEqual(record[tls.TLSServerDHParams].p, "1234")
        self.assertEqual(record[tls.TLSServerDHParams].g, "2")
        self.assertEqual(record[tls.TLSServerDHParams].y_s, "5")
        self.assertEqual(record[tls.TLSServerDHParams].sig, "456")

    def test_when_server_key_exchange_is_ecdh_then_it_is_dissected_correctly(self):
        record = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(),
                                                                 tls.TLSHandshake() / tls.TLSServerKeyExchange() /
                                                                 tls.TLSServerECDHParams(p="1234", sig="456")])
        self.assertTrue(record.haslayer(tls.TLSServerECDHParams))
        record = tls.TLSRecord(str(record))
        self.assertTrue(record.haslayer(tls.TLSServerECDHParams))
        self.assertEqual(record[tls.TLSServerECDHParams].p, "1234")
        self.assertEqual(record[tls.TLSServerECDHParams].sig, "456")

    def test_when_client_key_exchange_is_dh_then_it_is_dissected_correctly(self):
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.key_exchange = tls.TLSKexNames.DHE
        record = tls.TLSRecord(ctx=tls_ctx) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() /
                                                                                                 tls.TLSClientDHParams(data="3456")])
        self.assertTrue(record.haslayer(tls.TLSClientKeyExchange))
        self.assertTrue(record.haslayer(tls.TLSClientDHParams))
        record = tls.TLSRecord(str(record), ctx=tls_ctx)
        self.assertTrue(record.haslayer(tls.TLSClientKeyExchange))
        self.assertTrue(record.haslayer(tls.TLSClientDHParams))
        self.assertEqual(record[tls.TLSClientDHParams].data, "3456")

    def test_when_client_key_exchange_is_rsa_then_it_is_dissected_correctly(self):
        tls_ctx = tlsc.TLSSessionCtx()
        tls_ctx.negotiated.key_exchange = tls.TLSKexNames.RSA
        record = tls.TLSRecord(ctx=tls_ctx) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientKeyExchange() /
                                                                            tls.TLSClientRSAParams(data="3456")])
        self.assertTrue(record.haslayer(tls.TLSClientKeyExchange))
        self.assertTrue(record.haslayer(tls.TLSClientRSAParams))
        record = tls.TLSRecord(str(record), ctx=tls_ctx)
        self.assertTrue(record.haslayer(tls.TLSClientKeyExchange))
        self.assertTrue(record.haslayer(tls.TLSClientRSAParams))
        self.assertEqual(record[tls.TLSClientRSAParams].data, "3456")


class TestTLSPlaintext(unittest.TestCase):

    def test_built_plaintext_has_no_mac_and_padding_when_unspecified(self):
        plaintext = tls.TLSPlaintext(data="AAAA")
        self.assertEqual(str(plaintext), "AAAA")

    def test_built_plaintext_includes_mac_and_padding_if_not_empty(self):
        data = "A" * 4
        mac = "B" * 16
        padding = "C" * 19
        plaintext = tls.TLSPlaintext(data=data, mac=mac, padding=padding)
        self.assertEqual(len(data) + len(mac) + len(padding) + 1, len(str(plaintext)))
        self.assertEqual(plaintext.mac, mac)
        self.assertEqual(plaintext.padding, padding)
        self.assertEqual(ord(str(plaintext)[-1]), len(padding))
        self.assertEqual("%s%s%s%s" % (data, mac, padding, chr(len(padding))), str(plaintext))


class TestPCAP(unittest.TestCase):

    def setUp(self):
        self.records = []
        self.pkts = (p for p in rdpcap(env_local_file('RSA_WITH_AES_128_CBC_SHA.pcap')) if p.haslayer(tls.SSL))
        for p in (pkt for pkt in self.pkts):
            self.records += p.records
        unittest.TestCase.setUp(self)

    def test_pcap_hello_conditional_extensions_length(self):
        for r in (rec for rec in self.records if rec.haslayer(tls.TLSServerHello) or rec.haslayer(tls.TLSClientHello)):
            self.assertTrue("extensions_length=" in repr(r))
            self.assertEqual(r[tls.TLSHandshake].extensions_length, len(''.join(str(e) for e in r[tls.TLSHandshake].extensions)))

    def test_pcap_record_order(self):
        pkts = self.records
        pkts.reverse()
        # client hello
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshakes))
        self.assertTrue(record.haslayer(tls.TLSClientHello))
        extensions = record[tls.TLSClientHello].extensions
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtECPointsFormat))
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtEllipticCurves))
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtSessionTicketTLS))
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtHeartbeat))
        # server hello
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshakes))
        self.assertTrue(record.haslayer(tls.TLSServerHello))
        extensions = record[tls.TLSServerHello].extensions
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtRenegotiationInfo))
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtSessionTicketTLS))
        self.assertTrue(e for e in extensions if e.haslayer(tls.TLSExtHeartbeat))
        # certificate list
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshakes))
        self.assertTrue(record.haslayer(tls.TLSCertificateList))
        self.assertEqual(len(record[tls.TLSCertificateList].certificates), 1)
        self.assertTrue(record.haslayer(x509.X509Cert))
        try:
            record[tls.TLSCertificate].data.pubkey
        except AttributeError as ae:
            self.fail(ae)
        try:
            record[tls.TLSCertificate].data.signature
        except AttributeError as ae:
            self.fail(ae)
        # server hello done
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshakes))
        self.assertEquals(record[tls.TLSHandshake].type, tls.TLSHandshakeType.SERVER_HELLO_DONE)
        # client key exchange
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshakes))
        self.assertTrue(record.haslayer(tls.TLSClientKeyExchange))
        # TODO: Client and Server KEX cannot be dissected without a TLS context
        # self.assertTrue(record.haslayer(tls.TLSClientRSAParams))
        # self.assertEqual(record[tls.TLSClientRSAParams].data)
        self.assertEqual(
            str(
                record[
                    tls.TLSClientKeyExchange])[
                2:],
            '\x9es\xdf\xe0\xf2\xd0@2D\x9a4\x7fW\x86\x10\xea=\xc5\xe2\xf9\xa5iC\xc9\x0b\x00~\x911W\xfc\xc5e\x18\rD\xfdQ\xf8\xda\x8az\xab\x16\x03\xeb\xac#n\x8d\xdd\xbb\xf4u\xe7\xb7\xa3\xce\xdbgk}0*')
        # Change Cipher Spec
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSChangeCipherSpec))
        self.assertEqual(record[tls.TLSChangeCipherSpec].message, '\x01')
        # TLSFinished - encrypted
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertEquals(record[tls.TLSRecord].content_type, tls.TLSContentType.HANDSHAKE)
        self.assertTrue(record.haslayer(tls.TLSCiphertext))
        self.assertEqual(record[tls.TLSRecord].length, 0x30)
        self.assertEqual(
            record[
                tls.TLSCiphertext].data,
            "\x15\xcbz[-\xc0'\t(b\x95D\x9f\xa1\x1eNj\xfbI\x9dj$D\xc6\x8e&\xbc\xc1(\x8c'\xcc\xa2\xba\xec8cnd\xd8R\x94\x17\x96a\xfd\x9cT")
        # Handshake - new session ticket
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSHandshakes))
        self.assertTrue(record.haslayer(tls.TLSSessionTicket))
        self.assertEqual(record[tls.TLSSessionTicket].lifetime, 7200)
        self.assertEqual(record[tls.TLSSessionTicket].ticket_length, 0xa0)
        self.assertEqual(
            record[
                tls.TLSSessionTicket].ticket,
            '\xd4\xee\xb0\x9b\xb5\xa2\xd3\x00W\x84Y\xec\r\xbf\x05\x0c\xd5\xb9\xe2\xf82\xb5\xec\xce\xe2\x9c%%\xd9>J\x94[\xca\x18+\x0f_\xf6s8b\xcd\xcc\xf129\xe4^0\xf3\x94\xf5\xc5\x94:\x8c\x8e\xe5\x12J\x1e\xd81\xb5\x17\t\xa6Li\xca\xae\xfb\x04\x17dT\x9e\xc2\xfa\xf3m\xe9\xa5\xed\xa6e\xfe/\xf3\xc6\xcex@\xf7e\xe0\x13\xd3w\xc7\xc5y\x16VL0\x94\xcf\xb0<\x00\x91\xbd\x86\x08\x9f/\x05g\x03o\xa7;\xb96\xf2\x80O`]L\xc4B]\x02D\xba1\x8f9\x8e\x0c\x1e\xa8&O>\x01\x96\xb3o\xc6%\xe40\x03\xd6:}')
        # Change Cipher Spec
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertTrue(record.haslayer(tls.TLSChangeCipherSpec))
        self.assertEqual(record[tls.TLSChangeCipherSpec].message, '\x01')
        # TLSFinished - encrypted
        record = pkts.pop()
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertEquals(record[tls.TLSRecord].content_type, tls.TLSContentType.HANDSHAKE)
        self.assertTrue(record.haslayer(tls.TLSCiphertext))
        self.assertEqual(
            record[
                tls.TLSCiphertext].data,
            '%\xb8X\xc1\xa6?\xf8\xbd\xe6\xae\xbd\x98\xd4u\xa5E\x1b\xd8jpy\x86)NOd\xba\xe7\x1f\xcaK\x96\x9b\xf7\x0bP\xf5O\xfd\xda\xda\xcd\xcdK\x12.\xdf\xd5')
        # some more encrypted traffic
        for _ in xrange(6):
            # Application data - encrypted - 6 times
            record = pkts.pop()
            self.assertTrue(record.haslayer(tls.TLSRecord))
            self.assertEquals(record[tls.TLSRecord].content_type, tls.TLSContentType.APPLICATION_DATA)
            self.assertTrue(record.haslayer(tls.TLSCiphertext))
            self.assertEqual(record.length, len(record[tls.TLSCiphertext].data))
        # check if there are any more pakets?
        with self.assertRaises(IndexError):
            record = pkts.pop()


class TestToRaw(unittest.TestCase):

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

        self.tls_ctx = tlsc.TLSSessionCtx()
        self.tls_ctx.server_ctx.load_rsa_keys(self.pem_priv_key)
        # SSLv2
        self.record_version = 0x0002
        # TLSv1.0
        self.hello_version = 0x0301
        self.cipher_suite = tls.TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA
        # NULL
        self.comp_method = 0x0
        self.client_hello = tls.TLSRecord(version=self.record_version) / \
                            tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSClientHello(version=self.hello_version,
                                                                                                  compression_methods=[self.comp_method],
                                                                                                  cipher_suites=[self.cipher_suite])])
        self.tls_ctx.insert(self.client_hello)
        self.server_hello = tls.TLSRecord(version=self.hello_version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(
            version=self.hello_version, compression_method=self.comp_method, cipher_suite=self.cipher_suite)])
        self.tls_ctx.insert(self.server_hello)
        # Build method to generate EPMS automatically in TLSSessionCtx
        self.client_kex = tls.TLSRecord(version=self.hello_version) / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
            tls.TLSClientKeyExchange() / tls.TLSClientRSAParams(data=self.tls_ctx.get_encrypted_pms())])
        self.tls_ctx.insert(self.client_kex)
        unittest.TestCase.setUp(self)

    def test_invalid_tls_session_context_raises_error(self):
        with self.assertRaises(ValueError):
            tls.to_raw(None, None)

    def test_unsupported_layer_raises_error(self):
        pkt = tls.TLSClientHello()
        with self.assertRaises(KeyError):
            tls.to_raw(pkt, self.tls_ctx)

    def test_record_payload_is_identical_to_raw_payload(self):
        pkt = tls.TLSPlaintext(data=b"ABCD")
        raw = tls.to_raw(pkt, self.tls_ctx, include_record=False)
        record = tls.TLSRecord() / raw
        self.assertEqual(len(record[tls.TLSRecord]) - 0x5, len(raw))
        self.assertEqual(str(record[tls.TLSRecord].payload), raw)

    def test_all_hooks_are_called_when_defined(self):
        # Return the data twice, but do not compress
        def custom_compress(comp_method, pre_compress_data):
            return pre_compress_data * 2

        # Return cleartext, null mac, null padding
        def pre_encrypt(crypto_container):
            crypto_container.mac = b""
            crypto_container.padding = b""
            crypto_container.padding_len = b""
            return crypto_container

        # Return cleartext
        encrypt = lambda x: str(x)
        data = b"ABCD"
        pkt = tls.TLSPlaintext(data=data)
        raw = tls.to_raw(pkt, self.tls_ctx, include_record=False, compress_hook=custom_compress,
                         pre_encrypt_hook=pre_encrypt, encrypt_hook=encrypt)
        self.assertEqual(len(raw), len(data) * 2)
        self.assertEqual(raw, data * 2)

    def test_tls_record_header_is_updated_when_output(self):
        data = b"ABCD" * 389
        pkt = tls.TLSPlaintext(data=data)
        # Use server side keys, include TLSRecord header in output
        self.tls_ctx.client = False
        record = tls.to_raw(pkt, self.tls_ctx, include_record=True)
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertEqual(record.content_type, 0x17)
        self.assertEqual(record.version, self.tls_ctx.negotiated.version)

    def test_format_of_tls_finished_is_as_specified_in_rfc(self):
        def encrypt(crypto_container):
            self.assertEqual(crypto_container.crypto_data.data, "\x14\x00\x00\x0c%s" % self.tls_ctx.get_verify_data())
            self.assertEqual(len(crypto_container.mac), SHA.digest_size)
            self.assertEqual(len(crypto_container.padding), 11)
            self.assertTrue(all(map(lambda x: True if x == chr(11) else False, crypto_container.padding)))
            return "A" * 48

        client_finished = tls.TLSRecord(content_type=0x16) / tls.to_raw(tls.TLSHandshakes(handshakes=[tls.TLSHandshake() /
                                                                                                      tls.TLSFinished(data=self.tls_ctx.get_verify_data())]),
                                                                        self.tls_ctx, include_record=False, encrypt_hook=encrypt)
        pkt = tls.TLS(str(client_finished))
        # 4 bytes of TLSHandshake header, 12 bytes of verify_data, 20 bytes of
        # HMAC SHA1, 11 bytes of padding, 1 padding length byte
        self.assertEqual(pkt[tls.TLSRecord].length, len(tls.TLSHandshake()) + 12 + SHA.digest_size + 11 + 1)


class TestTLSCertificate(unittest.TestCase):

    def setUp(self):
        '''
        //default openssl 1.0.1f server.pem
        subject= C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = Test Server Cert
        issuer= C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = OpenSSL Test Intermediate CA
        '''
        rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+', re.DOTALL)
        self.pem_cert = """-----BEGIN CERTIFICATE-----
MIID5zCCAs+gAwIBAgIJALnu1NlVpZ6zMA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNV
BAYTAlVLMRYwFAYDVQQKDA1PcGVuU1NMIEdyb3VwMSIwIAYDVQQLDBlGT1IgVEVT
VElORyBQVVJQT1NFUyBPTkxZMSUwIwYDVQQDDBxPcGVuU1NMIFRlc3QgSW50ZXJt
ZWRpYXRlIENBMB4XDTExMTIwODE0MDE0OFoXDTIxMTAxNjE0MDE0OFowZDELMAkG
A1UEBhMCVUsxFjAUBgNVBAoMDU9wZW5TU0wgR3JvdXAxIjAgBgNVBAsMGUZPUiBU
RVNUSU5HIFBVUlBPU0VTIE9OTFkxGTAXBgNVBAMMEFRlc3QgU2VydmVyIENlcnQw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzhPOSNtyyRspmeuUpxfNJ
KCLTuf7g3uQ4zu4iHOmRO5TQci+HhVlLZrHF9XqFXcIP0y4pWDbMSGuiorUmzmfi
R7bfSdI/+qIQt8KXRH6HNG1t8ou0VSvWId5TS5Dq/er5ODUr9OaaDva7EquHIcMv
vPQGuI+OEAcnleVCy9HVEIySrO4P3CNIicnGkwwiAud05yUAq/gPXBC1hTtmlPD7
TVcGVSEiJdvzqqlgv02qedGrkki6GY4S7GjZxrrf7Foc2EP+51LJzwLQx3/JfrCU
41NEWAsu/Sl0tQabXESN+zJ1pDqoZ3uHMgpQjeGiE0olr+YcsSW/tJmiU9OiAr8R
AgMBAAGjgY8wgYwwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBeAwLAYJYIZI
AYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQW
BBSCvM8AABPR9zklmifnr9LvIBturDAfBgNVHSMEGDAWgBQ2w2yI55X+sL3szj49
hqshgYfa2jANBgkqhkiG9w0BAQUFAAOCAQEAqb1NV0B0/pbpK9Z4/bNjzPQLTRLK
WnSNm/Jh5v0GEUOE/Beg7GNjNrmeNmqxAlpqWz9qoeoFZax+QBpIZYjROU3TS3fp
yLsrnlr0CDQ5R7kCCDGa8dkXxemmpZZLbUCpW2Uoy8sAA4JjN9OtsZY7dvUXFgJ7
vVNTRnI01ghknbtD+2SxSQd3CWF6QhcRMAzZJ1z1cbbwGDDzfvGFPzJ+Sq+zEPds
xoVLLSetCiBc+40ZcDS5dV98h9XD7JMTQfxzA7mNGv73JoZJA6nFgj+ADSlJsY/t
JBv+z1iQRueoh9Qeee+ZbRifPouCB8FDx+AltvHTANdAq0t/K3o+pplMVA==
-----END CERTIFICATE-----"""
        self.der_cert = rex_pem.findall(self.pem_cert)[0].decode("base64")
        self.pem_priv_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA84TzkjbcskbKZnrlKcXzSSgi07n+4N7kOM7uIhzpkTuU0HIv
h4VZS2axxfV6hV3CD9MuKVg2zEhroqK1Js5n4ke230nSP/qiELfCl0R+hzRtbfKL
tFUr1iHeU0uQ6v3q+Tg1K/Tmmg72uxKrhyHDL7z0BriPjhAHJ5XlQsvR1RCMkqzu
D9wjSInJxpMMIgLndOclAKv4D1wQtYU7ZpTw+01XBlUhIiXb86qpYL9NqnnRq5JI
uhmOEuxo2ca63+xaHNhD/udSyc8C0Md/yX6wlONTRFgLLv0pdLUGm1xEjfsydaQ6
qGd7hzIKUI3hohNKJa/mHLElv7SZolPTogK/EQIDAQABAoIBAADq9FwNtuE5IRQn
zGtO4q7Y5uCzZ8GDNYr9RKp+P2cbuWDbvVAecYq2NV9QoIiWJOAYZKklOvekIju3
r0UZLA0PRiIrTg6NrESx3JrjWDK8QNlUO7CPTZ39/K+FrmMkV9lem9yxjJjyC34D
AQB+YRTx+l14HppjdxNwHjAVQpIx/uO2F5xAMuk32+3K+pq9CZUtrofe1q4Agj9R
5s8mSy9pbRo9kW9wl5xdEotz1LivFOEiqPUJTUq5J5PeMKao3vdK726XI4Z455Nm
W2/MA0YV0ug2FYinHcZdvKM6dimH8GLfa3X8xKRfzjGjTiMSwsdjgMa4awY3tEHH
674jhAECgYEA/zqMrc0zsbNk83sjgaYIug5kzEpN4ic020rSZsmQxSCerJTgNhmg
utKSCt0Re09Jt3LqG48msahX8ycqDsHNvlEGPQSbMu9IYeO3Wr3fAm75GEtFWePY
BhM73I7gkRt4s8bUiUepMG/wY45c5tRF23xi8foReHFFe9MDzh8fJFECgYEA9EFX
4qAik1pOJGNei9BMwmx0I0gfVEIgu0tzeVqT45vcxbxr7RkTEaDoAG6PlbWP6D9a
WQNLp4gsgRM90ZXOJ4up5DsAWDluvaF4/omabMA+MJJ5kGZ0gCj5rbZbKqUws7x8
bp+6iBfUPJUbcqNqFmi/08Yt7vrDnMnyMw2A/sECgYEAiiuRMxnuzVm34hQcsbhH
6ymVqf7j0PW2qK0F4H1ocT9qhzWFd+RB3kHWrCjnqODQoI6GbGr/4JepHUpre1ex
4UEN5oSS3G0ru0rC3U4C59dZ5KwDHFm7ffZ1pr52ljfQDUsrjjIMRtuiwNK2OoRa
WSsqiaL+SDzSB+nBmpnAizECgYBdt/y6rerWUx4MhDwwtTnel7JwHyo2MDFS6/5g
n8qC2Lj6/fMDRE22w+CA2esp7EJNQJGv+b27iFpbJEDh+/Lf5YzIT4MwVskQ5bYB
JFcmRxUVmf4e09D7o705U/DjCgMH09iCsbLmqQ38ONIRSHZaJtMDtNTHD1yi+jF+
OT43gQKBgQC/2OHZoko6iRlNOAQ/tMVFNq7fL81GivoQ9F1U0Qr+DH3ZfaH8eIkX
xT0ToMPJUzWAn8pZv0snA0um6SIgvkCuxO84OkANCVbttzXImIsL7pFzfcwV/ERK
UM6j0ZuSMFOCr/lGPAoOQU0fskidGEHi1/kW+suSr28TqsyYZpwBDQ==
-----END RSA PRIVATE KEY-----
        """
        self.der_priv_key = rex_pem.findall(self.pem_priv_key)[0].decode("base64")
        unittest.TestCase.setUp(self)

    def test_tls_certificate_x509(self):
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSCertificateList() / tls.TLS10Certificate(
            certificates=[tls.TLSCertificate(data=x509.X509Cert(self.der_cert))])])

        self.assertEqual(str(pkt[tls.TLSCertificateList].certificates[0].data), self.der_cert)
        self.assertEqual(str(pkt[tls.TLSCertificate].data), self.der_cert)
        try:
            pkt[tls.TLSCertificate].data.pubkey
        except AttributeError as ae:
            self.fail(ae)
        # serialize and dissect the same packet
        pkt_d = tls.SSL(str(pkt))
        self.assertEqual(str(pkt_d[tls.TLSCertificateList].certificates[0].data), self.der_cert)
        self.assertEqual(str(pkt_d[tls.TLSCertificate].data), self.der_cert)
        try:
            pkt_d[tls.TLSCertificate].data.pubkey
        except AttributeError as ae:
            self.fail(ae)
        # compare pubkeys
        self.assertEqual(pkt[tls.TLSCertificate].data.pubkey, pkt_d[tls.TLSCertificate].data.pubkey)

    def test_tls_certificate_multiple_x509(self):
        # issue #27
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSCertificateList() / tls.TLS10Certificate(
            certificates=[tls.TLSCertificate(data=x509.X509Cert(self.der_cert)),
                          tls.TLSCertificate(data=x509.X509Cert(self.der_cert)),
                          tls.TLSCertificate(data=x509.X509Cert(self.der_cert))])])

        self.assertEqual(len(pkt[tls.TLSCertificateList].certificates), 3)

        for tlscert in pkt[tls.TLSCertificateList].certificates:
            self.assertEqual(str(tlscert.data), self.der_cert)
            try:
                tlscert.data.pubkey
            except AttributeError as ae:
                self.fail(ae)

        # serialize and dissect the same packet
        pkt_d = tls.SSL(str(pkt))
        self.assertEqual(len(pkt_d[tls.TLSCertificateList].certificates), 3)

        for tlscert in pkt_d[tls.TLSCertificateList].certificates:
            self.assertEqual(str(tlscert.data), self.der_cert)
            try:
                tlscert.data.pubkey
            except AttributeError as ae:
                self.fail(ae)
            # compare pubkeys
            self.assertEqual(pkt[tls.TLSCertificate].data.pubkey, tlscert.data.pubkey)

    def test_tls_certificate_x509_pubkey(self):
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSCertificateList() / tls.TLS10Certificate(
            certificates=[tls.TLSCertificate(data=x509.X509Cert(self.der_cert))])])
        # dissect and extract pubkey
        pkt = tls.SSL(str(pkt))

        keystore1 = tlsk.RSAKeystore.from_der_certificate(self.der_cert)
        pubkey_extract_from_der = keystore1.public
        keystore2 = tlsk.RSAKeystore.from_der_certificate(pkt[tls.TLSCertificate].data)
        pubkey_extract_from_tls_certificate = keystore2.public

        self.assertEqual(pubkey_extract_from_der, pubkey_extract_from_tls_certificate)

        self.assertTrue(pubkey_extract_from_der.can_encrypt())
        self.assertTrue(pubkey_extract_from_der.can_sign())

        self.assertTrue(pubkey_extract_from_tls_certificate.can_encrypt())
        self.assertTrue(pubkey_extract_from_tls_certificate.can_sign())

    def test_when_using_tls13_then_certificates_are_dissected_differently(self):
        pkt = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSCertificateList() / tls.TLS13Certificate(
            request_context="1234",
            certificates=[tls.TLSCertificateEntry(cert_data=x509.X509Cert(self.der_cert),
                                                  extensions=[tls.TLSExtension(type=tls.TLSExtensionType.SIGNED_CERTIFICATE_TIMESTAMP) /
                                                              "whatever"]),
                          tls.TLSCertificateEntry(cert_data=x509.X509Cert(self.der_cert)),
                          tls.TLSCertificateEntry(cert_data=x509.X509Cert(self.der_cert))])])
        self.assertTrue(pkt.haslayer(tls.TLSCertificateList))
        self.assertFalse(pkt.haslayer(tls.TLS10Certificate))
        self.assertTrue(pkt.haslayer(tls.TLS13Certificate))
        self.assertEqual(pkt[tls.TLS13Certificate].request_context, "1234")
        self.assertEqual(len(pkt[tls.TLS13Certificate].certificates), 3)
        self.assertTrue(pkt[tls.TLS13Certificate].certificates[0].haslayer(tls.TLSCertificateEntry))
        self.assertTrue(pkt[tls.TLS13Certificate].certificates[0].haslayer(tls.TLSExtension))
        self.assertEqual(pkt[tls.TLS13Certificate].certificates[0].extensions[0].type, tls.TLSExtensionType.SIGNED_CERTIFICATE_TIMESTAMP)
        pkt = tls.TLSRecord(str(pkt))
        self.assertTrue(pkt.haslayer(tls.TLSCertificateList))
        self.assertFalse(pkt.haslayer(tls.TLS10Certificate))
        self.assertTrue(pkt.haslayer(tls.TLS13Certificate))
        self.assertEqual(pkt[tls.TLS13Certificate].request_context, "1234")
        self.assertEqual(len(pkt[tls.TLS13Certificate].certificates), 3)
        self.assertTrue(pkt[tls.TLS13Certificate].certificates[0].haslayer(tls.TLSCertificateEntry))
        self.assertTrue(pkt[tls.TLS13Certificate].certificates[0].haslayer(tls.TLSExtension))
        self.assertEqual(pkt[tls.TLS13Certificate].certificates[0].extensions[0].type, tls.TLSExtensionType.SIGNED_CERTIFICATE_TIMESTAMP)


class TestTLSExtensions(unittest.TestCase):
    def test_when_client_hello_has_a_key_share_extension_it_is_dissected_as_a_client_hello_key_share(self):
        client_shares = [tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP256R1, key_exchange=b"1234"),
                         tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP521R1, key_exchange=b"5678")]
        keyshares = tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSClientHelloKeyShare(client_shares=client_shares)
        extensions = [tls.TLSExtension() / tls.TLSExtSupportedGroups(), keyshares, tls.TLSExtension() / tls.TLSExtSupportedVersions(),
                      tls.TLSExtension() / tls.TLSExtALPN(protocol_name_list=[tls.TLSALPNProtocol(data=b"h2")])]
        client_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / \
                                                                       tls.TLSClientHello(cipher_suites=[tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384],
                                                                                          extensions=extensions)])
        parsed_record = tls.TLS(str(client_hello))
        parsed_client_hello = parsed_record[tls.TLSClientHello]

        self.assertEqual(str(parsed_record), str(client_hello))
        self.assertNotEqual(parsed_client_hello.extensions, [])
        self.assertEqual(len(parsed_client_hello.extensions), len(extensions))
        self.assertTrue(parsed_client_hello.extensions[0].haslayer(tls.TLSExtSupportedGroups))
        self.assertTrue(parsed_client_hello.extensions[1].haslayer(tls.TLSExtKeyShare))
        self.assertTrue(parsed_client_hello.extensions[1].haslayer(tls.TLSClientHelloKeyShare))
        self.assertTrue(parsed_client_hello.extensions[2].haslayer(tls.TLSExtSupportedVersions))
        self.assertTrue(parsed_client_hello.extensions[3].haslayer(tls.TLSExtALPN))
        for extension in parsed_client_hello.extensions:
            self.assertFalse(extension.haslayer(tls.TLSServerHelloKeyShare))
            self.assertFalse(extension.haslayer(tls.TLSHelloRetryRequestKeyShare))
        key_share = parsed_client_hello[tls.TLSClientHelloKeyShare]
        self.assertEqual(len(key_share.client_shares), len(client_shares))
        for i, v in enumerate(key_share.client_shares):
            self.assertEqual(str(v), str(client_shares[i]))
            self.assertEqual(v.named_group, client_shares[i].named_group)
            self.assertEqual(v.key_exchange, client_shares[i].key_exchange)

    def test_when_server_hello_has_a_key_share_extension_it_is_dissected_as_a_server_hello_key_share(self):
        server_share = tls.TLSKeyShareEntry(named_group=tls.TLSSupportedGroup.SECP256R1, key_exchange=b"A"*12)
        keyshare = tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSServerHelloKeyShare(server_share=server_share)
        extensions = [tls.TLSExtension() / tls.TLSExtSignatureAlgorithms(), keyshare, tls.TLSExtension() / tls.TLSExtCookie(cookie=b"B"*12)]
        server_hello = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSServerHello(version=tls.TLSVersion.TLS_1_3,
                                                                                 cipher_suite=tls.TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                                                                                 extensions=extensions)])
        parsed_record = tls.TLS(str(server_hello))
        parsed_server_hello = parsed_record[tls.TLSServerHello]

        self.assertEqual(str(parsed_record), str(server_hello))
        self.assertNotEqual(parsed_server_hello.extensions, [])
        self.assertEqual(len(parsed_server_hello.extensions), len(extensions))
        self.assertTrue(parsed_server_hello.extensions[0].haslayer(tls.TLSExtSignatureAlgorithms))
        self.assertTrue(parsed_server_hello.extensions[1].haslayer(tls.TLSExtKeyShare))
        self.assertTrue(parsed_server_hello.extensions[1].haslayer(tls.TLSServerHelloKeyShare))
        self.assertTrue(parsed_server_hello.extensions[2].haslayer(tls.TLSExtCookie))
        for extension in parsed_server_hello.extensions:
            self.assertFalse(extension.haslayer(tls.TLSClientHelloKeyShare))
            self.assertFalse(extension.haslayer(tls.TLSHelloRetryRequestKeyShare))
        key_share = parsed_server_hello[tls.TLSServerHelloKeyShare]
        self.assertEqual(len(key_share.server_share), len(server_share))
        self.assertEqual(str(key_share.server_share), str(server_share))
        self.assertEqual(key_share.server_share.named_group, server_share.named_group)
        self.assertEqual(key_share.server_share.key_exchange, server_share.key_exchange)

    def test_when_hello_retry_request_has_a_key_share_extension_it_is_dissected_as_a_hello_retry_request_key_share(self):
        hhr_share = tls.TLSExtension() / tls.TLSExtKeyShare() / tls.TLSHelloRetryRequestKeyShare(selected_group=tls.TLSSupportedGroup.FFDHE2048)
        extensions = [hhr_share, tls.TLSExtension() / tls.TLSExtCookie(b"A"*15)]

        hrr = tls.TLSRecord() / tls.TLSHandshakes(handshakes=[tls.TLSHandshake() / tls.TLSHelloRetryRequest(extensions=extensions)])
        parsed_record = tls.TLS(str(hrr))
        parsed_hrr = parsed_record[tls.TLSHelloRetryRequest]

        self.assertEqual(str(parsed_record), str(hrr))
        self.assertNotEqual(parsed_hrr.extensions, [])
        self.assertEqual(len(parsed_hrr.extensions), len(extensions))
        self.assertTrue(parsed_hrr.extensions[0].haslayer(tls.TLSExtKeyShare))
        self.assertTrue(parsed_hrr.extensions[0].haslayer(tls.TLSHelloRetryRequestKeyShare))
        self.assertTrue(parsed_hrr.extensions[1].haslayer(tls.TLSExtCookie))
        for extension in parsed_hrr.extensions:
            self.assertFalse(extension.haslayer(tls.TLSClientHelloKeyShare))
            self.assertFalse(extension.haslayer(tls.TLSServerHelloKeyShare))
        key_share = parsed_hrr[tls.TLSHelloRetryRequestKeyShare]
        self.assertEqual(key_share.selected_group, hhr_share.selected_group)


class TestTLSTopLevelFunctions(unittest.TestCase):

    def test_tls_payload_fragmentation_raises_error_with_negative_size(self):
        with self.assertRaises(ValueError):
            tls.tls_fragment_payload("AAAA", size=-1)


if __name__ == "__main__":
    unittest.main()
