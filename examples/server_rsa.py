# -*- coding: utf-8 -*-

import os
import socket
import sys

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls.ssl_tls_crypto import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.layers.ssl_tls_crypto import *

with open(os.path.join(basedir, "tests/integration/keys/cert.der"), "rb") as f:
    cert = f.read()
certificates = TLSCertificate(data=cert)


socket_ = socket.socket()
socket_.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
tls_socket = TLSSocket(socket_, client=False)
tls_socket.bind(("", 8443))
tls_socket.listen(1)
tls_socket.tls_ctx.rsa_load_keys_from_file(os.path.join(basedir, "tests/integration/keys/key.pem"))
c_socket, _ = tls_socket.accept()

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

print ((c_socket.tls_ctx))


