#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import socket
import sys

def _send(sock, pkt):
    sock.sendall(pkt)

def _recv(sock, size=8192):
    resp = []
    while True:
        try:
            data = sock.recv(size)
            if not data:
                break
            resp.append(data)
        except socket.timeout as st:
            break
    return "".join(resp)

def tls_hello(sock, ctx):
    client_hello = TLSRecord(version="TLS_1_0")/TLSHandshake()/TLSClientHello(version="TLS_1_0", compression_methods=[0],
                                                                              cipher_suites=(TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA))

    try:
        _send(sock, str(client_hello))
        ctx.insert(client_hello)
        server_hello = TLS(_recv(sock))
        ctx.insert(server_hello)
    except socket.timeout as st:
        print("No response from peer during TLS Handshake", file=sys.stderr)

def tls_client_key_exchange(sock, ctx):
    client_key_exchange = TLSRecord()/TLSHandshake()/TLSClientKeyExchange()/ctx.get_encrypted_pms()
    client_ccs = TLSRecord()/TLSChangeCipherSpec()
    client_pkt = TLS.from_records([client_key_exchange, client_ccs])
    try:
        ctx.insert(client_pkt)
        _send(sock, str(client_pkt))
        client_finished = to_raw(TLSFinished(), ctx)
        ctx.insert(client_finished)
        _send(sock, str(client_finished))
        server_finished = TLS(_recv(sock), ctx=ctx)
        ctx.insert(server_finished)
        server_finished.show()
    except socket.timeout as st:
        print("No reponse from peer after TLS Finished", file=sys.stderr)

def tls_client(ip, priv_key=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(ip)
        sock.settimeout(1)
        print("Connected to server: %s" % (ip,))
    except socket.timeout as te:
        print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
    else:
        ssl_ctx = TLSSessionCtx()
        tls_hello(sock, ssl_ctx)
        tls_client_key_exchange(sock, ssl_ctx)
        print("Finished handshake. Sending application data (GET request)")
        app_data = to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), ssl_ctx)
        _send(sock, str(app_data))
        data = _recv(sock)
        resp = TLS(data, ctx=ssl_ctx)
        print("Got response from server")
        resp.show()
        close_notify = to_raw(TLSAlert(level=TLSAlertLevel.WARNING, description=TLSAlertDescription.CLOSE_NOTIFY), ssl_ctx)
        _send(sock, str(close_notify))
        print("Sending close notify to tear down connection")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv)>2:
        server = (sys.argv[1],int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    tls_client(server)
