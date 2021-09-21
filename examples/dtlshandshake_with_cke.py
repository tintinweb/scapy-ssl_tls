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

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))

tls_version = TLSVersion.DTLS_1_0
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
    with open(os.path.join(basedir, "tests/integration/keys/scapy-tls-client.crt.der"), "rb") as f:
        client_cert = f.read()
    certificate = TLSCertificate(data=client_cert)

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with TLSSocket(sockfd, client=True) as tls_socket:
        try:
            tls_socket.connect(server)
            print("Connected to server: %s" % (server,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (server,), file=sys.stderr)
        else:
            try:
                server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
                server_kex.show()
                server_hello.show()
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            else:
                app_data = DTLSRecord(version=tls_version, sequence=1, epoch=1) / TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: 10.102.59.251\r\n\r\n")
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
        server = ("10.102.59.251", 4433)
    dtls_client(server)
