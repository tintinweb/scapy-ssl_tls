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


tls_version = TLSVersion.TLS_1_2
ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
extensions = [TLSExtension() / TLSExtSessionTicketTLS(data="")]


def tls_client(ip):
    with TLSSocket(socket.socket(), client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            print("Connected to server: %s" % (ip,))
            try:
                server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
                http_response = tls_socket.do_round_trip(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_socket.tls_ctx))
                http_response.show()
                print(tls_socket.tls_ctx)
            except TLSProtocolError as pe:
                print(pe)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
