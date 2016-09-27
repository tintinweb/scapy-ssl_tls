#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print (_function)
import os
import socket
import sys

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

tls_version = TLSVersion.TLS_1_2


def tls_hello(sock):
    client_hello = TLSRecord(version=tls_version) / TLSHandshake() /\
                   TLSClientHello(version=tls_version, compression_methods=[TLSCompressionMethod.NULL, ],
                                  cipher_suites=[TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256, ])
                                  # cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA, ])
                                  # cipher_suites=[TLSCipherSuite.RSA_WITH_RC4_128_SHA, ])
                                  # cipher_suites=[TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA, ])
                                  # cipher_suites=[TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA, ])
    sock.sendall(client_hello)
    server_hello = sock.recvall()
    server_hello.show()


def tls_client_key_exchange(sock):
    client_key_exchange = TLSRecord(version=tls_version) / TLSHandshake() / sock.tls_ctx.get_client_kex_data()
    client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
    sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
    sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
    server_finished = sock.recvall()
    server_finished.show()


def tls_client(ip, priv_key=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(ip)
        sock = TLSSocket(sock, client=True)
        print (("Connected to server: %s" % (ip,)))
    except socket.timeout as te:
        print (("Failed to open connection to server: %s" % (ip,), file=sys.stderr))
    else:
        tls_hello(sock)
        tls_client_key_exchange(sock)
        print (("Finished handshake. Sending application data (GET request)"))
        sock.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), sock.tls_ctx))
        resp = sock.recvall()
        print (("Got response from server"))
        resp.show()
        print ((sock.tls_ctx))
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
