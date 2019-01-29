#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

from scapy_ssl_tls import multidigest_pkcs1_15 as Sig_multi_PKCS1_v1_5

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))

version = TLSVersion.DTLS_1_0
#ciphers = [TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA]
ciphers = [0x0035]
tls_server_names = "abc.com"
tls_session_ticket = "myticket"
extensions=[
            TLSExtension() /
            TLSExtServerNameIndication(server_names=TLSServerName(data=tls_server_names)),
            TLSExtension() /
            TLSExtSessionTicketTLS(data=tls_session_ticket),
            ]


def dtls_client(server):
    with open(os.path.join(basedir, "tests/integration/keys/rsa_clnt1.der"), "rb") as f:
        client_cert = f.read()
    certificate = TLSCertificate(data=client_cert)

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with TLSSocket(sockfd, client=True) as tls_socket:
        try:
            tls_socket.connect(server)
            print("Connected to server: %s" % (server,))
            tls_socket.tls_ctx.client_ctx.load_rsa_keys_from_file(os.path.join(
                basedir, "tests/integration/keys/rsa_clnt1ky"))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (server,), file=sys.stderr)
        else:
            try:
                client_hello = DTLSRecord(version=version, sequence=0) / \
                               DTLSHandshake(fragment_offset=0) / \
                               DTLSClientHello(version=version,
                                               compression_methods=TLSCompressionMethod.NULL,
                                               cipher_suites=ciphers,
                                               extensions=extensions)
                resp1 = tls_do_round_trip(tls_socket, client_hello)
                resp1.show()
                client_cert = DTLSRecord(version=version, sequence=2) / \
                              DTLSHandshake(fragment_offset=0, sequence=1) / \
                              DTLSCertificateList() / \
                              TLS10Certificate(certificates=certificate)

                client_key_exchange = DTLSRecord(version=version, sequence=3) / \
                                      DTLSHandshake(fragment_offset=0, sequence=2) / DTLSClientKeyExchange() / \
                                      tls_socket.tls_ctx.get_client_kex_data()

                p = TLS.from_records([client_cert, client_key_exchange])
                tls_socket.sendall(p)
                #tls_socket.do_round_trip(p, recv=False)
                #tls_socket.do_round_trip([client_cert, client_key_exchange], False)

                sig = tls_socket.tls_ctx.compute_client_cert_verify(digest=Sig_multi_PKCS1_v1_5)
                #sig = sign_cv(tls_socket.tls_ctx, 1024 // 8)

                client_cert_verify = DTLSRecord(version=version, sequence=4) / \
                                     DTLSHandshake(fragment_offset=0, sequence=3) / \
                                     DTLSCertificateVerify(sig=sig)

                #tls_socket.do_round_trip(client_cert_verify, False)
                tls_socket.sendall(client_cert_verify)

                client_ccs = DTLSRecord(version=version, sequence=5) / DTLSChangeCipherSpec()

                tls_socket.sendall(client_ccs)

                client_finished = DTLSRecord(version=version, sequence=0, epoch=1) / \
                                    DTLSHandshake(fragment_offset=0, sequence=4) / \
                                        DTLSFinished(data=tls_socket.tls_ctx.get_verify_data())

                #resp2 = tls_socket.do_round_trip([client_ccs, client_finished], False)
                resp2 = tls_do_round_trip(tls_socket, client_finished)
                resp2.show()

            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            else:
                app_data = DTLSRecord(version=version, sequence=1, epoch=1) / TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: 10.102.59.251\r\n\r\n")
                tls_socket.sendall(app_data)
                resp = tls_socket.recvall()
                print("Got response from server")
                resp.show()
            finally:
                print(tls_socket.tls_ctx)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("10.102.57.144", 4433)
    dtls_client(server)
