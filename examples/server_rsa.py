# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import socket
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls.ssl_tls_crypto import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.layers.ssl_tls_crypto import *


if __name__ == "__main__":
    bind = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) >2 else ("127.0.0.1", 8443)
    if len(sys.argv)==4:
        server_cert = server_key = sys.argv[3]
    elif len(sys.argv)==5:
        server_cert = sys.argv[3]
        server_key = sys.argv[4]
    else:
        server_cert = "tests/integration/keys/cert.der"
        server_key = "tests/integration/keys/key.pem"

    print (server_cert) 
    with open(server_cert, "rb") as f:
        cert = f.read()
    certificates = TLSCertificate(data=cert)


    socket_ = socket.socket()
    socket_.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    tls_socket = TLSSocket(socket_, client=False)
    tls_socket.bind(bind)
    tls_socket.listen(1)
    print("server ready!")
    tls_socket.tls_ctx.server_ctx.load_rsa_keys_from_file(server_key)
    c_socket, _ = tls_socket.accept()
    print ("got client: %r" % c_socket)
    r = c_socket.recvall()
    version = r[TLSClientHello].version
    server_hello = TLSRecord(version=version) / TLSHandshake() / TLSServerHello(version=version)
    server_certs = TLSRecord(version=version) / TLSHandshake() / TLSCertificateList(certificates=certificates)
    server_done = TLSRecord(version=version) / TLSHandshake(type=TLSHandshakeType.SERVER_HELLO_DONE)
    records = TLS.from_records([server_hello, server_certs, server_done])
    c_socket.sendall(records)

    r = c_socket.recvall()

    server_ccs = TLSRecord(version=version) / TLSChangeCipherSpec()
    c_socket.sendall(TLS.from_records([server_ccs]))
    c_socket.sendall(to_raw(TLSFinished(), c_socket.tls_ctx))

    r = c_socket.recvall()
    c_socket.sendall(to_raw(TLSPlaintext(data="It works!\n"), c_socket.tls_ctx))
    c_socket.sendall(to_raw(TLSAlert(), c_socket.tls_ctx))

    print(c_socket.tls_ctx)
    sys.exit(0)
