#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print (_function)
import os
import socket
import sys

from Crypto.Hash import SHA256

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
    from scapy.all import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.all import *


def do_tls_mutual_auth(host):
    with open(os.path.join(basedir, "tests/integration/keys/scapy-tls-client.crt.der"), "rb") as f:
        client_cert = f.read()
    certificate = TLSCertificate(data=client_cert)

    tls_version = TLSVersion.TLS_1_2

    socket_ = socket.socket()
    tls_socket = TLSSocket(socket_, client=True)
    tls_socket.connect(host)
    tls_socket.tls_ctx.rsa_load_keys_from_file(os.path.join(basedir,
                                                            "tests/integration/keys/scapy-tls-client.key.pem"),
                                                            client=True)

    client_hello = TLSRecord(version=tls_version) / TLSHandshake() /\
                   TLSClientHello(version=tls_version, compression_methods=[TLSCompressionMethod.NULL, ],
                                  cipher_suites=[TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256, ])
    tls_socket.sendall(client_hello)
    server_hello = tls_socket.recvall()
    server_hello.show()

    client_cert = TLSRecord(version=tls_version) / TLSHandshake() / TLSCertificateList(certificates=certificate)
    client_key_exchange = TLSRecord(version=tls_version) / TLSHandshake() / tls_socket.tls_ctx.get_client_kex_data()
    p = TLS.from_records([client_cert, client_key_exchange])
    tls_socket.sendall(p)

    sig_hash_alg = TLSSignatureHashAlgorithm(hash_alg=TLSHashAlgorithm.SHA256, sig_alg=TLSSignatureAlgorithm.RSA)
    sig = tls_socket.tls_ctx.get_client_signed_handshake_hash(SHA256.new())
    # sig = sig[:128] + chr(ord(sig[128]) ^ 0xff) + sig[129:]
    client_cert_verify = TLSRecord(version=tls_version) / TLSHandshake() / \
                         TLSCertificateVerify(alg=sig_hash_alg,
                                              sig=sig)
    tls_socket.sendall(client_cert_verify)

    client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
    tls_socket.sendall(client_ccs)
    tls_socket.sendall(to_raw(TLSFinished(), tls_socket.tls_ctx))
    server_finished = tls_socket.recvall()
    server_finished.show()

    tls_socket.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_socket.tls_ctx))
    resp = tls_socket.recvall()
    print (("Got response from server"))
    resp.show()
    print ((tls_socket.tls_ctx))


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    do_tls_mutual_auth(server)

