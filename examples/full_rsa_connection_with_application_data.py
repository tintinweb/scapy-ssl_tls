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
# ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA384]
# ciphers = [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA]
# ciphers = [TLSCipherSuite.RSA_WITH_RC4_128_SHA]
# ciphers = [TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA]
# ciphers = [TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA]
extensions = [TLSExtension() / TLSExtECPointsFormat(),
              TLSExtension() / TLSExtSupportedGroups()]


def tls_client(ip):
    with TLSSocket(client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
            print("Connected to server: %s" % (ip,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            try:
                server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
                server_hello.show()
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            else:
                resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
                print("Got response from server")
                resp.show()
            finally:
                print(tls_socket.tls_ctx)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
