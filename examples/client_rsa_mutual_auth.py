#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import os


import Cryptodome


basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy.all import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.all import *

from scapy_ssl_tls import multidigest_pkcs1_15 as Sig_multi_PKCS1_v1_5

def do_tls_mutual_auth(host):
    with open(os.path.join(basedir, "tests/integration/keys/rsa_clnt1.der"), "rb") as f:
        client_cert = f.read()
    certificate = TLSCertificate(data=client_cert)

    tls_version = TLSVersion.TLS_1_0

    with TLSSocket(socket.socket(), client=True) as tls_socket:
        tls_socket.connect(host)
        tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
            basedir, "tests/integration/keys/rsa_clnt1ky"))

        client_hello = TLSRecord(version=tls_version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSClientHello(version=tls_version,
                                                                cipher_suites=[0x0035])])
        server_hello = tls_socket.do_round_trip(client_hello)
        # server_hello.show()

        client_cert = TLSRecord(version=tls_version) / \
                      TLSHandshakes(handshakes=[TLSHandshake() / TLSCertificateList() /
                                                TLS10Certificate(certificates=certificate)])
        client_key_exchange = TLSRecord(version=tls_version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        tls_socket.tls_ctx.get_client_kex_data()])
        p = TLS.from_records([client_cert, client_key_exchange])
        tls_socket.do_round_trip(p, recv=False)

        sig = tls_socket.tls_ctx.compute_client_cert_verify(digest=Sig_multi_PKCS1_v1_5)   #TLS1.0
        #sig = tls_socket.tls_ctx.compute_client_cert_verify(digest=Cryptodome.Hash.SHA256)  #TLS1.2

        #client_cert_verify = TLSRecord(version=tls_version) / \
        #                     TLSHandshakes(handshakes=[TLSHandshake() /
        #                                               TLS12CertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
        #                                                                    sig=sig)])     #TLS1.2

        client_cert_verify = TLSRecord(version=tls_version) / \
                             TLSHandshakes(handshakes=[TLSHandshake() /
                                                       TLSCertificateVerify(sig=sig)])      #TLS1.0

        tls_socket.do_round_trip(client_cert_verify, recv=False)

        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        tls_socket.do_round_trip(client_ccs, recv=False)
        server_finished = tls_socket.do_round_trip(TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        server_finished.show()

        resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
        print("Got response from server")
        resp.show()
        print(tls_socket.tls_ctx)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("10.102.59.251", 443)
    do_tls_mutual_auth(server)
