# -*- coding: utf-8 -*-

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
ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLSCipherSuite.EMPTY_RENEGOTIATION_INFO_SCSV]
extensions = [TLSExtension() / TLSExtRenegotiationInfo(data="")]


def tls_client(ip):
    with TLSSocket(socket.socket(), client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
            tls_ctx = tls_socket.tls_ctx
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            print("Connected to server: %s" % (ip,))
            try:
                server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
                client_verify_data = tls_ctx.client_ctx.verify_data
                renegotiation = [TLSExtension() / TLSExtRenegotiationInfo(data=client_verify_data)]
                # RSA_WITH_AES_128_CBC_SHA DHE_RSA_WITH_AES_256_CBC_SHA256
                server_hello, server_kex = tls_socket.do_secure_renegotiation(tls_version, [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA], renegotiation)
                # client_hello = TLSHandshake() / TLSClientHello(version=tls_version, cipher_suites=, extensions=renegotiation)
                # r = tls_socket.do_round_trip(to_raw(client_hello, tls_ctx))
                server_kex.show()
                # http_response = tls_socket.do_round_trip(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), tls_socket.tls_ctx))
                # http_response.show()
            except TLSProtocolError as pe:
                print(pe)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
