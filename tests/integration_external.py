#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Integration testsuite
    * OpenSSL s_server
    * python built-in ssl server
    * Java SSL server

Todo:
    * refactor!
    * add tests for sniffer and other examples
    * move common stuff to own module to have a clean testsuite

"""
from __future__ import with_statement
from __future__ import print_function
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
import unittest
import socket
import time

from helper import wait_for_server, OpenSslServer, JavaTlsServer, PythonTlsServer

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))


class TlsConnectionHelper(object):
    """
    Container for tls messages
    """
    def tls_hello(self):
        client_hello = TLSRecord(version=self.tls_version) / TLSHandshakes(handshakes=[TLSHandshake() /
                                                                                       TLSClientHello(version=self.tls_version,
                                                                                                      compression_methods=self.compression_methods,
                                                                                                      cipher_suites=self.cipher_suites)])
        server_hello = self.sock.do_round_trip(client_hello)
        return server_hello

    def tls_client_key_exchange(self):
        client_key_exchange = TLSRecord(version=self.tls_version) / TLSHandshakes(handshakes=[TLSHandshake() / self.sock.tls_ctx.get_client_kex_data()])
        client_ccs = TLSRecord(version=self.tls_version) / TLSChangeCipherSpec()
        self.sock.do_round_trip(TLS.from_records([client_key_exchange, client_ccs]), False)

        server_finished = self.sock.do_round_trip(TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=self.sock.tls_ctx.get_verify_data())]))
        return server_finished

    def connect(self, target, tls_version, compression_methods, cipher_suites):
        self.tls_version, self.compression_methods, self.cipher_suites = tls_version, compression_methods, cipher_suites
        self.sock = TLSSocket(socket.socket(), client=True)
        self.sock.connect(target)
        return self.sock

    def close(self):
        if self.sock:
            self.sock.close()


class TestHandshakeWithData(unittest.TestCase):

    def setUp(self):
        self.tlsutil = TlsConnectionHelper()
        # todo iterate server implementations
        # self.tls_server = PythonTlsServer(args=(("127.0.0.1", 8443),
        #                                        os.path.join(basedir,"./tests/files/openssl_1_0_1_f_server.pem")))
        self.tls_server = OpenSslServer(args=(("127.0.0.1", 8443),
                                              os.path.join(basedir,"./tests/files/openssl_1_0_1_f_server.pem"),
                                              os.path.join(basedir,"./tests/files/dsa_server.pem")))
        # self.tls_server = JavaTlsServer(args=(("localhost", 8443),))
        wait_for_server(self.tls_server.bind)

    def tearDown(self):
        self.tls_server.kill()

    def do_test(self, target, **kwargs):
        """
        perform ssl handshake with http get
        :param target:
        :param tls_version:
        :param compression_methods:
        :param cipher_suites:
        :return:
        """
        sock = self.tlsutil.connect(target, **kwargs)
        self.assertTrue(sock, "socket connect to %s" % (target,))
        print("Connected to server: %s" % (target,))

        server_hello = self.tlsutil.tls_hello()
        self.assertIn(TLSRecord, server_hello)
        self.assertIn(TLSHandshake, server_hello)
        self.assertIn(TLSServerHello, server_hello)
        self.assertIn(TLSCertificateList, server_hello)
        self.assertIn(TLSCertificate, server_hello)
        self.assertIn(X509Cert, server_hello)
        server_finish = self.tlsutil.tls_client_key_exchange()
        print("Finished handshake. Sending application data (GET request)")
        self.tlsutil.sock.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
        resp = self.tlsutil.sock.recvall()
        print("Got response from server")
        self.tlsutil.close()
        return resp

    def test_external_tls_1_2_NULL_ECDHE_RSA_WITH_AES_128_CBC_SHA256(self):
        tls_version = TLSVersion.TLS_1_2
        compression_methods = [TLSCompressionMethod.NULL, ]
        cipher_suites = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256, ]
        target = self.tls_server.bind
        self.do_test(target=target, tls_version=tls_version, compression_methods=compression_methods,
                     cipher_suites=cipher_suites)

    def test_external_tls_1_2_NULL_RSA_WITH_AES_128_CBC_SHA(self):
        tls_version = TLSVersion.TLS_1_2
        compression_methods = [TLSCompressionMethod.NULL, ]
        cipher_suites = [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA, ]
        target = self.tls_server.bind
        self.do_test(target=target, tls_version=tls_version, compression_methods=compression_methods,
                     cipher_suites=cipher_suites)

    def test_external_tls_1_2_NULL_RSA_WITH_RC4_128_SHA(self):
        tls_version = TLSVersion.TLS_1_2
        compression_methods = [TLSCompressionMethod.NULL, ]
        cipher_suites = [TLSCipherSuite.RSA_WITH_RC4_128_SHA, ]
        target = self.tls_server.bind
        self.do_test(target=target, tls_version=tls_version, compression_methods=compression_methods,
                     cipher_suites=cipher_suites)

    @unittest.skip("DSA not supportorted by Java and Python out of the box. This results in FP test failures. Skipping out for now.")
    def test_external_tls_1_2_NULL_DHE_DSS_WITH_AES_128_CBC_SHA(self):
         tls_version = TLSVersion.TLS_1_2
         compression_methods = [TLSCompressionMethod.NULL, ]
         cipher_suites = [TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA, ]
         target = self.tls_server.bind
         self.do_test(target=target, tls_version=tls_version, compression_methods=compression_methods,
                      cipher_suites=cipher_suites)

if __name__ == '__main__':
    # todo remove_me
    unittest.main()
