#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import socket
import sys
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *

def tls_hello(sock):
    client_hello = TLSRecord(version="TLS_1_0")/TLSHandshake()/TLSClientHello(version="TLS_1_0", compression_methods=[0],
                                                                              cipher_suites=(TLSCipherSuite.RSA_WITH_RC4_128_SHA))
    sock.sendall(client_hello)
    server_hello = sock.recvall()
    server_hello.show()

def tls_client_key_exchange(sock):
    client_key_exchange = TLSRecord()/TLSHandshake()/TLSClientKeyExchange()/sock.tls_ctx.get_encrypted_pms()
    client_ccs = TLSRecord()/TLSChangeCipherSpec()
    sock.sendall(TLS.from_records([client_key_exchange, client_ccs]))
    sock.sendall(to_raw(TLSFinished(), sock.tls_ctx))
    server_finished = sock.recvall()
    server_finished.show()

def tls_client(ip, priv_key=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(ip)
        sock = TLSSocket(sock, client=True)
        print("Connected to server: %s" % (ip,))
    except socket.timeout as te:
        print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
    else:
        tls_hello(sock)
        tls_client_key_exchange(sock)
        print("Finished handshake. Sending application data (GET request)")
        sock.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), sock.tls_ctx))
        resp = sock.recvall()
        print("Got response from server")
        resp.show()
        close_notify = sock.sendall(to_raw(TLSAlert(level=TLSAlertLevel.WARNING, description=TLSAlertDescription.CLOSE_NOTIFY), sock.tls_ctx))
        print("Sending close notify to tear down connection")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv)>2:
        server = (sys.argv[1],int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
