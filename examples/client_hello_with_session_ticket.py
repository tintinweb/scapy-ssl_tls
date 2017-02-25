# -*- coding: utf-8 -*-
try:
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)

    host = (sys.argv[1], int(sys.argv[2]))
    version = TLSVersion.TLS_1_2
    cipher = TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA
    ticket = ""
    master_secret = ""

    with TLSSocket(socket.socket(), client=True) as tls_socket:
        tls_socket.connect(host)
        tls_ctx = tls_socket.tls_ctx

        pkt = TLSRecord() / \
            TLSHandshakes(handshakes=[TLSHandshake() /
                                      TLSClientHello(version=version,
                                                     cipher_suites=[cipher],
                                                     extensions=[TLSExtension() /
                                                                 TLSExtSessionTicketTLS(data="")])])


        pkt.show()
        tls_socket.sendall(pkt)
        resp = tls_socket.recvall()
        resp.show()
        client_key_exchange = TLSRecord(version=version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        tls_ctx.get_client_kex_data()])

        client_ccs = TLSRecord(version=version) / TLSChangeCipherSpec()
        tls_socket.sendall(TLS.from_records([client_key_exchange, client_ccs]))
        tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
                                                     TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        server_finished = tls_socket.recvall()
        server_finished.show()
        ticket = server_finished[TLSSessionTicket].ticket
        tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
        resp = tls_socket.recvall()
        resp.show()
        master_secret = tls_ctx.master_secret

    print("First session context: %s" % tls_ctx)

    with TLSSocket(socket.socket(), client=True) as tls_socket:
        tls_socket.connect(host)
        tls_ctx = tls_socket.tls_ctx
        tls_socket.tls_ctx.resume_session(master_secret)

        pkt = TLSRecord() / TLSHandshakes(handshakes=[TLSHandshake() /
                                                      TLSClientHello(version=version,
                                                                     cipher_suites=[cipher],
                                                                     extensions=[TLSExtension() /
                                                                                 TLSExtSessionTicketTLS(data=ticket)])])
        pkt.show()
        tls_socket.sendall(pkt)
        resp = tls_socket.recvall()
        resp.show()
        tls_socket.sendall(TLSRecord(version=version) / TLSChangeCipherSpec())
        tls_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
                                                     TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        tls_socket.sendall(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"))
        tls_socket.recvall()

    print("Resumed session context: %s" % tls_ctx)
