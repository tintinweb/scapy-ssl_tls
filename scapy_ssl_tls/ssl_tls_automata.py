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

    # GENERIC ERROR - print received data if available
    @ATMT.state(error=1)
    def ERROR(self, p=None):
        if p:
            p.show()
        return

    # GENERIC END - return server's response
    @ATMT.state(final=1)
    def END(self, p):
        return ''.join(pkt[TLSPlaintext].data for pkt in p.records)



class TLSServerAutomata(Automaton):
    """"A Simple TLS Server Automata
    
        TLSServerAutomata.graph()
        auto_srv = TLSServerAutomata(debug=9,
                                 target=("127.0.0.1",65009),
                                 tls_version="TLS_1_1",
                                 cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                                 response="HTTP/1.1 200 OK\r\n\r\n")
        auto_srv.run()
    """
    def parse_args(self, 
                   target, 
                   tls_version='TLS_1_1', 
                   response="HTTP/1.1 200 OK\r\n\r\n", 
                   cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                   timeout=4.0, 
                   **kwargs):
        Automaton.parse_args(self, **kwargs)
        self.target = target
        self.tls_version = tls_version
        self.response = response
        self.cipher_suite = cipher_suite
        self.timeout = timeout
        self.tlssock = None
        self.srv_sock = None
        self.peer = None
        self.debug(1,"parse_args - done")

    # GENERIC BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.debug(1,"BEGIN")
    
    @ATMT.condition(BEGIN)
    def listen(self):
        raise self.WAIT_FOR_CLIENT_CONNECTION()
    
    @ATMT.action(listen)
    def do_bind(self):
        self.debug(1,"dobind")
        self.srv_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.srv_sock.bind(self.target)
        self.srv_sock.listen(1)
        
        self.debug(1,"server bound to %s:%d"%self.target)
        
    @ATMT.state()
    def WAIT_FOR_CLIENT_CONNECTION(self):
        self.debug(1,"accept")
        self.peer = self.srv_sock.accept()
        self.tlssock = TLSSocket(self.peer[0], client=False)
    
    @ATMT.condition(WAIT_FOR_CLIENT_CONNECTION)
    def recv_client_hello(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        p.show()
        if not p.haslayer(TLSClientHello):
            raise self.ERROR(p)
        raise self.CLIENT_HELLO_RECV()
    
    @ATMT.state()
    def CLIENT_HELLO_RECV(self):
        pass
    
    @ATMT.condition(CLIENT_HELLO_RECV)
    def send_server_hello(self):
        raise self.SERVER_HELLO_SENT()
    
    @ATMT.action(send_server_hello)
    def do_send_server_hello(self):
        rec_hs = TLSRecord(version=self.tls_version) / TLSHandshake()
        server_hello = rec_hs/TLSServerHello(version=self.tls_version, 
                                             compression_method=TLSCompressionMethod.NULL,
                                             cipher_suite=self.cipher_suite)
        server_hello.show()
        self.tlssock.sendall(server_hello)
        
        #TODO: remove static server cert/key 
        #pem = ssl_tls_crypto.pem_get_objects(open("../tests/files/openssl_1_0_1_f_server.pem",'r').read())
        
        #key = pem['RSA PRIVATE KEY']['full'].replace("\n","")
        key = "MIIEpAIBAAKCAQEA84TzkjbcskbKZnrlKcXzSSgi07n+4N7kOM7uIhzpkTuU0HIvh4VZS2axxfV6hV3CD9MuKVg2zEhroqK1Js5n4ke230nSP/qiELfCl0R+hzRtbfKLtFUr1iHeU0uQ6v3q+Tg1K/Tmmg72uxKrhyHDL7z0BriPjhAHJ5XlQsvR1RCMkqzuD9wjSInJxpMMIgLndOclAKv4D1wQtYU7ZpTw+01XBlUhIiXb86qpYL9NqnnRq5JIuhmOEuxo2ca63+xaHNhD/udSyc8C0Md/yX6wlONTRFgLLv0pdLUGm1xEjfsydaQ6qGd7hzIKUI3hohNKJa/mHLElv7SZolPTogK/EQIDAQABAoIBAADq9FwNtuE5IRQnzGtO4q7Y5uCzZ8GDNYr9RKp+P2cbuWDbvVAecYq2NV9QoIiWJOAYZKklOvekIju3r0UZLA0PRiIrTg6NrESx3JrjWDK8QNlUO7CPTZ39/K+FrmMkV9lem9yxjJjyC34DAQB+YRTx+l14HppjdxNwHjAVQpIx/uO2F5xAMuk32+3K+pq9CZUtrofe1q4Agj9R5s8mSy9pbRo9kW9wl5xdEotz1LivFOEiqPUJTUq5J5PeMKao3vdK726XI4Z455NmW2/MA0YV0ug2FYinHcZdvKM6dimH8GLfa3X8xKRfzjGjTiMSwsdjgMa4awY3tEHH674jhAECgYEA/zqMrc0zsbNk83sjgaYIug5kzEpN4ic020rSZsmQxSCerJTgNhmgutKSCt0Re09Jt3LqG48msahX8ycqDsHNvlEGPQSbMu9IYeO3Wr3fAm75GEtFWePYBhM73I7gkRt4s8bUiUepMG/wY45c5tRF23xi8foReHFFe9MDzh8fJFECgYEA9EFX4qAik1pOJGNei9BMwmx0I0gfVEIgu0tzeVqT45vcxbxr7RkTEaDoAG6PlbWP6D9aWQNLp4gsgRM90ZXOJ4up5DsAWDluvaF4/omabMA+MJJ5kGZ0gCj5rbZbKqUws7x8bp+6iBfUPJUbcqNqFmi/08Yt7vrDnMnyMw2A/sECgYEAiiuRMxnuzVm34hQcsbhH6ymVqf7j0PW2qK0F4H1ocT9qhzWFd+RB3kHWrCjnqODQoI6GbGr/4JepHUpre1ex4UEN5oSS3G0ru0rC3U4C59dZ5KwDHFm7ffZ1pr52ljfQDUsrjjIMRtuiwNK2OoRaWSsqiaL+SDzSB+nBmpnAizECgYBdt/y6rerWUx4MhDwwtTnel7JwHyo2MDFS6/5gn8qC2Lj6/fMDRE22w+CA2esp7EJNQJGv+b27iFpbJEDh+/Lf5YzIT4MwVskQ5bYBJFcmRxUVmf4e09D7o705U/DjCgMH09iCsbLmqQ38ONIRSHZaJtMDtNTHD1yi+jF+OT43gQKBgQC/2OHZoko6iRlNOAQ/tMVFNq7fL81GivoQ9F1U0Qr+DH3ZfaH8eIkXxT0ToMPJUzWAn8pZv0snA0um6SIgvkCuxO84OkANCVbttzXImIsL7pFzfcwV/ERKUM6j0ZuSMFOCr/lGPAoOQU0fskidGEHi1/kW+suSr28TqsyYZpwBDQ==".decode("base64")
        #cert = pem['CERTIFICATE']['full'].replace("\n","")
        cert = "MIID5zCCAs+gAwIBAgIJALnu1NlVpZ6zMA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNVBAYTAlVLMRYwFAYDVQQKDA1PcGVuU1NMIEdyb3VwMSIwIAYDVQQLDBlGT1IgVEVTVElORyBQVVJQT1NFUyBPTkxZMSUwIwYDVQQDDBxPcGVuU1NMIFRlc3QgSW50ZXJtZWRpYXRlIENBMB4XDTExMTIwODE0MDE0OFoXDTIxMTAxNjE0MDE0OFowZDELMAkGA1UEBhMCVUsxFjAUBgNVBAoMDU9wZW5TU0wgR3JvdXAxIjAgBgNVBAsMGUZPUiBURVNUSU5HIFBVUlBPU0VTIE9OTFkxGTAXBgNVBAMMEFRlc3QgU2VydmVyIENlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzhPOSNtyyRspmeuUpxfNJKCLTuf7g3uQ4zu4iHOmRO5TQci+HhVlLZrHF9XqFXcIP0y4pWDbMSGuiorUmzmfiR7bfSdI/+qIQt8KXRH6HNG1t8ou0VSvWId5TS5Dq/er5ODUr9OaaDva7EquHIcMvvPQGuI+OEAcnleVCy9HVEIySrO4P3CNIicnGkwwiAud05yUAq/gPXBC1hTtmlPD7TVcGVSEiJdvzqqlgv02qedGrkki6GY4S7GjZxrrf7Foc2EP+51LJzwLQx3/JfrCU41NEWAsu/Sl0tQabXESN+zJ1pDqoZ3uHMgpQjeGiE0olr+YcsSW/tJmiU9OiAr8RAgMBAAGjgY8wgYwwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBeAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBSCvM8AABPR9zklmifnr9LvIBturDAfBgNVHSMEGDAWgBQ2w2yI55X+sL3szj49hqshgYfa2jANBgkqhkiG9w0BAQUFAAOCAQEAqb1NV0B0/pbpK9Z4/bNjzPQLTRLKWnSNm/Jh5v0GEUOE/Beg7GNjNrmeNmqxAlpqWz9qoeoFZax+QBpIZYjROU3TS3fpyLsrnlr0CDQ5R7kCCDGa8dkXxemmpZZLbUCpW2Uoy8sAA4JjN9OtsZY7dvUXFgJ7vVNTRnI01ghknbtD+2SxSQd3CWF6QhcRMAzZJ1z1cbbwGDDzfvGFPzJ+Sq+zEPdsxoVLLSetCiBc+40ZcDS5dV98h9XD7JMTQfxzA7mNGv73JoZJA6nFgj+ADSlJsY/tJBv+z1iQRueoh9Qeee+ZbRifPouCB8FDx+AltvHTANdAq0t/K3o+pplMVA==".decode("base64")

        server_certificates = rec_hs / TLSCertificateList(certificates=[TLSCertificate(data=x509.X509Cert(cert))])
        server_certificates.show()
        self.tlssock.sendall(server_certificates)
        (rec_hs / TLSServerHelloDone()).show2()
        server_hello_done = TLSRecord(version=self.tls_version) / TLSHandshake(type=TLSHandshakeType.SERVER_HELLO_DONE)
        self.tlssock.sendall(server_hello_done)
    
    @ATMT.state()
    def SERVER_HELLO_SENT(self):
        pass
    
    @ATMT.condition(SERVER_HELLO_SENT)
    def recv_client_key_exchange(self):
        p = self.tlssock.recvall()
        p.show()
        if not p.haslayer(TLSClientKeyExchange):
            raise self.ERROR(p)
        raise self.CLIENT_KEY_EXCHANGE_RECV()
    
    @ATMT.state()
    def CLIENT_KEY_EXCHANGE_RECV(self):
        raise self.CLIENT_CHANGE_CIPHERSPEC_RECV()
    
    @ATMT.state()
    def CLIENT_CHANGE_CIPHERSPEC_RECV(self):
        raise self.CLIENT_FINISH_RECV()
    
    @ATMT.state()
    def CLIENT_FINISH_RECV(self):
        pass
  
    @ATMT.condition(CLIENT_FINISH_RECV)
    def send_server_ccs(self):
        raise self.SERVER_CCS_SENT()

    @ATMT.action(send_server_ccs)
    def do_send_server_ccs(self):
        tls_version = self.tlssock.tls_ctx.params.negotiated.version
        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        self.tlssock.sendall(client_ccs)

    @ATMT.state()
    def SERVER_CCS_SENT(self):
        pass
 
    @ATMT.condition(SERVER_CCS_SENT)
    def send_server_finish(self):
        raise self.SERVER_FINISH_SENT()
    
    @ATMT.action(send_server_finish)
    def do_send_server_finish(self):
        #TODO: fix server finish calculation
        finished = to_raw(TLSFinished(), self.tlssock.tls_ctx)
        self.tlssock.sendall(finished)
    
    @ATMT.state()
    def SERVER_FINISH_SENT(self):
        pass
    
    @ATMT.condition(SERVER_FINISH_SENT)
    def recv_client_appdata(self):
        p = self.tlssock.recvall()
        p.show()
        if not (p.haslayer(TLSRecord) and p[TLSRecord].content_type==TLSContentType.APPLICATION_DATA):
            raise self.ERROR(p)
        raise self.CLIENT_APPDATA_RECV(p)
    
    @ATMT.state()
    def CLIENT_APPDATA_RECV(self):
        pass
    
    @ATMT.condition(CLIENT_APPDATA_RECV)
    def send_server_response(self):
        raise self.SERVER_APPDATA_SENT()
    
    @ATMT.action(send_server_response)
    def do_send_server_response(self):
        self.tlssock.sendall(to_raw(TLSPlaintext(data=self.response), self.tlssock.tls_ctx))
    
    @ATMT.state()
    def SERVER_APPDATA_SENT(self):
        raise self.END()
    
    # GENERIC ERROR - print received data if available
    @ATMT.state(error=1)
    def ERROR(self, p=None):
        if p:
            p.show()
        return
    
    # GENERIC END - return server's response
    @ATMT.state(final=1)
    def END(self, p):
        return ''.join(pkt[TLSPlaintext].data for pkt in p.records)
