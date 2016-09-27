#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

import socket

from ssl_tls import *
from ssl_tls_crypto import *

from scapy.automaton import Automaton, ATMT


class TLSClientAutomata(Automaton):
    """"A Simple TLS Client Automata

        TLSClientAutomata.graph()
        auto_cli = TLSClientAutomata(debug=2,
                                 target=("google.com",443),
                                 tls_version="TLS_1_1",
                                 cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                                                TLSCipherSuite.RSA_WITH_RC4_128_SHA,
                                                TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA,
                                                TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA],
                                 request="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n")
        auto_cli.run()
    """
    def parse_args(self,
                   target,
                   tls_version='TLS_1_1',
                   request="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n",
                   cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA],
                   timeout=4.0,
                   **kwargs):
        Automaton.parse_args(self, **kwargs)
        self.target = target
        self.tls_version = tls_version
        self.request = request
        self.cipher_suites = cipher_suites
        self.timeout = timeout
        self.tlssock = None

    # GENERIC BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    # 1) check if already connected and connect if not
    @ATMT.condition(BEGIN, prio=1)
    def is_connected(self):
        if self.tlssock:
            raise self.CONNECTED()

    @ATMT.condition(BEGIN, prio=2)
    def not_connected(self):
        if not self.tlssock:
            raise self.CONNECTED()

    @ATMT.action(not_connected)
    def do_connect(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect(self.target)
        self.debug(1,"connected")
        self.tlssock = TLSSocket(sock, client=True)

    @ATMT.state()
    def CONNECTED(self):
        pass

    # 2) send client hello
    @ATMT.condition(CONNECTED)
    def send_client_hello(self):
        raise self.CLIENT_HELLO_SENT()

    @ATMT.action(send_client_hello)
    def do_send_client_hello(self):
        client_hello = TLSRecord(version=self.tls_version) / TLSHandshake() / TLSClientHello(version=self.tls_version,
                                                                                             compression_methods=(TLSCompressionMethod.NULL),
                                                                                             cipher_suites=self.cipher_suites)
        self.tlssock.sendall(client_hello)

    @ATMT.state()
    def CLIENT_HELLO_SENT(self):
        pass

    # 3) recv for server hello
    @ATMT.condition(CLIENT_HELLO_SENT)
    def recv_server_hello(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if not p.haslayer(TLSServerHello):
            raise self.ERROR(p)
        self.debug(10,"CIPHER: %s"%TLS_CIPHER_SUITES.get(p[TLSServerHello].cipher_suite,p[TLSServerHello].cipher_suite))
        raise self.SERVER_HELLO_RECV()

    @ATMT.state()
    def SERVER_HELLO_RECV(self):
        pass

    # 4) send client key exchange + CCS + finished
    @ATMT.condition(SERVER_HELLO_RECV)
    def send_client_key_exchange(self):
        raise self.CLIENT_KEY_EXCHANGE_SENT()

    @ATMT.action(send_client_key_exchange)
    def do_send_client_key_exchange(self):
        tls_version = self.tlssock.tls_ctx.params.negotiated.version
        client_key_exchange = TLSRecord(version=tls_version) / TLSHandshake() / self.tlssock.tls_ctx.get_client_kex_data()
        self.tlssock.sendall(client_key_exchange)

    @ATMT.state()
    def CLIENT_KEY_EXCHANGE_SENT(self):
        pass

    @ATMT.condition(CLIENT_KEY_EXCHANGE_SENT)
    def send_client_change_cipher_spec(self):
        tls_version = self.tlssock.tls_ctx.params.negotiated.version
        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        self.tlssock.sendall(client_ccs)
        raise self.CLIENT_CHANGE_CIPHERSPEC_SENT()

    @ATMT.state()
    def CLIENT_CHANGE_CIPHERSPEC_SENT(self):
        pass

    @ATMT.condition(CLIENT_CHANGE_CIPHERSPEC_SENT)
    def send_client_finish(self):
        finished = to_raw(TLSFinished(), self.tlssock.tls_ctx)
        self.tlssock.sendall(finished)
        raise self.CLIENT_FINISH_SENT()

    @ATMT.state()
    def CLIENT_FINISH_SENT(self):
        pass

    # 5) recv. server finished (not checking for CCS atm)
    @ATMT.condition(CLIENT_FINISH_SENT)
    def recv_server_finish(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if not (p.haslayer(TLSFinished) or
                (p.haslayer(TLSPlaintext) and SSL(str(TLSRecord(content_type='handshake')/p[TLSPlaintext].data)).haslayer(TLSFinished))):
            raise self.ERROR(p)
        raise self.SERVER_FINISH_RECV()

    @ATMT.state()
    def SERVER_FINISH_RECV(self):
        pass

    # 6) send application data
    @ATMT.condition(SERVER_FINISH_RECV)
    def send_client_request_http(self):
        raise self.CLIENT_APPDATA_SENT()

    @ATMT.action(recv_server_finish)
    def do_send_client_request(self):
        self.tlssock.sendall(to_raw(TLSPlaintext(data=self.request), self.tlssock.tls_ctx))

    @ATMT.state()
    def CLIENT_APPDATA_SENT(self):
        pass

    # 7) receive application data
    @ATMT.condition(CLIENT_APPDATA_SENT)
    def recv_server_appdata(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if not (p.haslayer(TLSRecord) and p[TLSRecord].content_type==TLSContentType.APPLICATION_DATA):
            raise self.ERROR(p)
        raise self.SERVER_APPDATA_RECV(p)

    @ATMT.state()
    def SERVER_APPDATA_RECV(self, p):
        raise self.END(p)

    # GENERIC ERROR - print ( received data if available)
    @ATMT.state(error=1)
    def ERROR(self, p=None):
        if p:
            p.show()
        return

    # GENERIC END - return server's response
    @ATMT.state(final=1)
    def END(self, p):
        return ''.join(pkt[TLSPlaintext].data for pkt in p.records)
