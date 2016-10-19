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
import subprocess
import socket, ssl
from multiprocessing import Process
import time

class PopenProcess(object):
    """
    subprocess.Popen wrapper
    """
    def __init__(self, target, args=(), cwd=None):
        self.pid = subprocess.Popen([target] + list(args), cwd=cwd)

    def kill(self):
        if self.pid:
            self.pid.kill()
            self.pid = None

    def __del__(self):
        self.kill()

class BackgroundProcess(object):
    """
    multiprocessing.Process wrapper
    """
    def __init__(self, target, args=()):
        self.pid = Process(target=target, args=args)

    def kill(self):
        if self.pid:
            self.pid.terminate()
            self.pid = None

    def __del__(self):
        self.kill()


def pytls_serve(bind=('', 8443),
                certfile="../tests/files/openssl_1_0_1_f_server.pem",
                ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ALL"):
    """
    python tls http echo server implementation
    :param bind:
    :param certfile:
    :param ssl_version:
    :param ciphers:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(bind)
    s.listen(1)
    while True:
        client_sock, addr = s.accept()
        ssl_sock = ssl.wrap_socket(client_sock,
                                   server_side=True,
                                   certfile=certfile,
                                   keyfile=certfile,
                                   ssl_version=ssl_version,
                                   ciphers=ciphers,)
        try:
            data = []
            chunk = ssl_sock.read()
            while chunk:
                data.apend(chunk)
                chunk = ssl_sock.read()
                if not chunk:
                    break
            # echo request
            head = "HTTP/1.1 200 OK\r\nContent-type: text/html\r\nX-SERVER: pytls\r\n\r\n"
            ssl_sock.write(head + ''.join(data))
        except:
            pass
        finally:
            ssl_sock.shutdown(socket.SHUT_RDWR)
            ssl_sock.close()

class PythonTlsServer(BackgroundProcess):
    """
    python.ssl
    """
    def __init__(self, target=pytls_serve, args=(('127.0.0.1',8443),
                                                 "../tests/files/openssl_1_0_1_f_server.pem",
                                                 ssl.PROTOCOL_TLSv1)):
        self.bind = args[0]
        self.args = args[1:]
        self.pid = Process(target=target, args=args)
        self.pid.start()

class OpenSslServer(PopenProcess):
    """
    OpenSSL s_server
    """
    def __init__(self, target="openssl", args=()):
        self.bind = args[0]
        self.args = args[1:]
        super(OpenSslServer, self).__init__(target=target, args=["s_server",
                                                                 "-accept", "%d"%self.bind[1],
                                                                 "-cert", self.args[0],
                                                                 "-cipher", "ALL",
                                                                 "-www"],)

class JavaTlsServer(PopenProcess):
    """
    Java tls server
    """
    def __init__(self, target="java", args=(), cwd=None):
        self.bind = args[0]
        self.args = args[1:]
        super(JavaTlsServer, self).__init__(target=target, args=["-cp", ".",
                                                                 '-Djavax.net.ssl.trustStore="keys/scapy-ssl_tls.jks"',
                                                                 '-Djavax.net.debug=ssl',
                                                                 'JSSEDebuggingServer'],
                                            cwd="../tests/integration/")

class TlsConnectionHelper(object):
    """
    Container for tls messages
    """
    def tls_hello(self):
        client_hello = TLSRecord(version=self.tls_version) / TLSHandshake() /\
            TLSClientHello(version=self.tls_version, compression_methods=self.compression_methods,
                           cipher_suites=self.cipher_suites)
        self.sock.sendall(client_hello)
        server_hello = self.sock.recvall()
        server_hello.show()
        return server_hello

    def tls_client_key_exchange(self):
        client_key_exchange = TLSRecord(version=self.tls_version) / TLSHandshake() / self.sock.tls_ctx.get_client_kex_data()
        client_ccs = TLSRecord(version=self.tls_version) / TLSChangeCipherSpec()
        self.sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
        self.sock.sendall(to_raw(TLSFinished(), self.sock.tls_ctx))
        server_finished = self.sock.recvall()
        server_finished.show()
        return server_finished

    def connect(self, target, tls_version, compression_methods, cipher_suites):
        self.tls_version, self.compression_methods, self.cipher_suites = tls_version, compression_methods, cipher_suites

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(target)
        self.sock = TLSSocket(self.sock, client=True)
        return self.sock

    def close(self):
        if self.sock:
            self.sock.close()


if not hasattr(unittest.TestCase, "assertIn"):
    """
    TODO: remove_me - superdirty py2.6 patch as assertIn is not in py2.6
    """
    def assertIn(self, a, b):
        if not a in b:
            raise Exception("%r not in %r" %(a, b))
    setattr(unittest.TestCase, "assertIn", assertIn)

class TestHandshakeWithData(unittest.TestCase):

    def setUp(self):
        self.tlsutil = TlsConnectionHelper()
        # todo iterate server implementations
        #self.tls_server = PythonTlsServer(args=(("127.0.0.1", 8443),"../tests/files/openssl_1_0_1_f_server.pem"))
        self.tls_server = OpenSslServer(args=(("127.0.0.1", 8443),"../tests/files/openssl_1_0_1_f_server.pem"))
        #self.tls_server = JavaTlsServer(args=(("127.0.0.1", 8443),))
        self.wait_for_server(self.tls_server.bind)

    def wait_for_server(self, target):
        """
        wait for target to accept new connections
        :param target:
        :return:
        """
        last_exception = None
        timeout = time.time() + 20
        while time.time() < timeout:
            csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                csock.connect(target)
                last_exception = None
                print("server socket ready")
                break
            except socket.error as se:
                last_exception = se
                print("server socket not yet ready")
        csock.close()
        if last_exception:
            raise last_exception

    def do_test(self, target, tls_version, compression_methods, cipher_suites):
        """
        perform ssl handshake with http get
        :param target:
        :param tls_version:
        :param compression_methods:
        :param cipher_suites:
        :return:
        """
        sock = self.tlsutil.connect(target, tls_version=tls_version, compression_methods=compression_methods,
                                    cipher_suites=cipher_suites)
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
        self.tlsutil.sock.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"),
                                         self.tlsutil.sock.tls_ctx))
        resp = self.tlsutil.sock.recvall()
        print("Got response from server")
        resp.show()
        print(self.tlsutil.sock.tls_ctx)
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
