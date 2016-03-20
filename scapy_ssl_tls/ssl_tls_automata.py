#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

import socket
import functools

from ssl_tls import *
from ssl_tls_crypto import *

from scapy.automaton import Automaton, ATMT

def hookable(f):
    @functools.wraps(f)
    def wrapped_f(*args, **kwargs):
        if args and isinstance(args[0],Automaton):
            obj = args[0]
            cb_f = obj.callbacks.get(f.__name__, None)
            if cb_f:
                obj.debug(1, "*** CALLBACK *** calling '%s' -> %s"%(f.__name__, cb_f))
                return cb_f(*args, **kwargs)
        return f(*args, **kwargs)
    return wrapped_f

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
        if p and self.debug_level >= 1:
            p.show()
        return

    # GENERIC END - return server's response
    @ATMT.state(final=1)
    def END(self, p):
        return ''.join(pkt[TLSPlaintext].data for pkt in p.records)

class TLSServerAutomata(Automaton):
    """"A Simple TLS Server Automata
    
        TLSServerAutomata.graph()
        with open(server_pem,'r') as f:
            pemcert = f.read()
        auto_srv = TLSServerAutomata(debug=9,
                                 bind=("0.0.0.0",8443),
                                 pemcert="-----BEGIN CERTIFICATE-----\n....",
                                 pemkey="-----BEGIN RSA PRIVATE KEY-----\n...",
                                 cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                                 response="HTTP/1.1 200 OK\r\n\r\n")
        auto_srv.run()
    """
    def __init__(self, *args, **kwargs):
        self.callbacks = {} # fname:func
        Automaton.__init__(self, *args, **kwargs)
        self.STATES = {TLSClientHello: 'CLIENT_HELLO_RECV',
                        TLSServerHello: 'SERVER_HELLO_SENT',
                        TLSCertificate: 'SERVER_CERTIFICATES_SENT',
                        TLSCertificateList: 'SERVER_CERTIFICATES_SENT',
                        TLSServerHelloDone: 'SERVER_HELLO_DONE_SENT',
                        TLSFinished: 'SERVER_FINISH_SENT',
                        TLSChangeCipherSpec: 'SERVER_CCS_SENT',
                        TLSClientKeyExchange: 'CLIENT_KEY_EXCHANGE_RECV',
                        TLSServerKeyExchange: 'SERVER_KEY_EXCHANGE_SENT',
                        TLSPlaintext: 'SERVER_APPDATA_SENT',
                        TLSDecryptablePacket: 'SERVER_APPDATA_SENT',
                       }
        self.ACTIONS = {TLSClientHello: 'rcv_client_hello',
                        TLSServerHello: 'send_server_hello',
                        TLSCertificate: 'send_server_certificates',
                        TLSCertificateList: 'send_server_certificates',
                        TLSServerHelloDone: 'send_server_hello_done',
                        TLSFinished: 'send_server_finish',
                        TLSChangeCipherSpec: 'send_server_ccs',
                        TLSClientKeyExchange: 'recv_client_key_exchange',
                        TLSServerKeyExchange: 'send_server_key_exchange',
                        TLSPlaintext: 'send_server_appdata',
                        TLSDecryptablePacket: 'send_server_appdata',
                        }
    
    def parse_args(self, 
                   bind, 
                   pemcert,
                   pemkey=None,
                   response="HTTP/1.1 200 OK\r\n\r\n", 
                   cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                   timeout=4.0, 
                   **kwargs):
        Automaton.parse_args(self, **kwargs)
        self.bind = bind
        self.pemcert = pemcert
        self.pemkey = pemkey if pemkey else pemcert
        self.tls_version = 'TLS_1_2'
        self.response = response
        self.cipher_suite = cipher_suite
        self.timeout = timeout
        self.tlssock = None
        self.srv_sock = None
        self.peer = None
        
        pemo = pem_get_objects(self.pemcert)
        for key_pk in (k for k in pemo.keys() if "CERTIFICATE" in k.upper()):
            self.dercert = ''.join(line for line in pemo[key_pk].get("full").strip().split("\n") if not "-" in line).decode("base64")
            break
        self.debug(1,"parse_args - done")
        
    def register_callback(self, fname, f):
        self.debug(1,"register callback: %s - %s"%(fname, repr(f)))
        self.callbacks[fname] = f

    # GENERIC BEGIN
    @ATMT.state(initial=1)
    @hookable
    def BEGIN(self):
        self.debug(1,"BEGIN")
    
    @ATMT.condition(BEGIN)
    @hookable
    def listen(self):
        raise self.WAIT_FOR_CLIENT_CONNECTION()
    
    @ATMT.action(listen)
    @hookable
    def do_bind(self):
        self.debug(1,"dobind %s "%repr(self.bind))
        self.srv_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.srv_tls_sock = TLSSocket(self.srv_sock, client=False)
        self.srv_tls_sock.bind(self.bind)
        self.srv_tls_sock.listen(1)
        
        pemo = pem_get_objects(self.pemkey)
        for key_pk in (k for k in pemo.keys() if "PRIVATE" in k.upper()):
            self.srv_tls_sock.tls_ctx.crypto.server.rsa.privkey, self.srv_tls_sock.tls_ctx.crypto.server.rsa.pubkey = self.srv_tls_sock.tls_ctx._rsa_load_keys(pemo[key_pk].get("full"))
            break

    @ATMT.state()
    @hookable
    def WAIT_FOR_CLIENT_CONNECTION(self):
        self.debug(1,"accept")
        self.tlssock, self.peer = self.srv_tls_sock.accept()
        self.debug(1,"new connection: %s"%repr(self.peer))
    
    @ATMT.condition(WAIT_FOR_CLIENT_CONNECTION)
    @hookable
    def recv_client_hello(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if self.debug_level >= 1:
            p.show()
        if not p.haslayer(TLSClientHello):
            raise self.ERROR(p)
        self.tls_version = p[TLSClientHello].version
        raise self.CLIENT_HELLO_RECV()
    
    @ATMT.state()
    @hookable
    def CLIENT_HELLO_RECV(self):
        pass
    
    @ATMT.condition(CLIENT_HELLO_RECV)
    @hookable
    def send_server_hello(self):
        raise self.SERVER_HELLO_SENT()
    
    @ATMT.action(send_server_hello)
    @hookable
    def do_send_server_hello(self):
        rec_hs = TLSRecord(version=self.tls_version) / TLSHandshake()
        server_hello = rec_hs/TLSServerHello(version=self.tls_version, 
                                             compression_method=TLSCompressionMethod.NULL,
                                             cipher_suite=self.cipher_suite)
        server_hello.show()
        self.tlssock.sendall(server_hello)
    
    @ATMT.state()
    @hookable
    def SERVER_HELLO_SENT(self):
        pass
    
    @ATMT.condition(SERVER_HELLO_SENT)
    @hookable
    def send_server_certificates(self):
        raise self.SERVER_CERTIFICATES_SENT()
    
    @ATMT.action(send_server_certificates)
    @hookable
    def do_send_server_certificates(self):
        rec_hs = TLSRecord(version=self.tls_version) / TLSHandshake()
        server_certificates = rec_hs / TLSCertificateList(certificates=[TLSCertificate(data=x509.X509Cert(self.dercert))])
        server_certificates.show()
        self.tlssock.sendall(server_certificates)
        
    @ATMT.state()
    @hookable
    def SERVER_CERTIFICATES_SENT(self):
        pass
    
    @ATMT.condition(SERVER_CERTIFICATES_SENT)
    @hookable
    def send_server_hello_done(self):
        raise self.SERVER_HELLO_DONE_SENT()
    
    @ATMT.action(send_server_hello_done)
    @hookable
    def do_send_server_hello_done(self):
        rec_hs = TLSRecord(version=self.tls_version) / TLSHandshake()
        (rec_hs / TLSServerHelloDone()).show2()
        server_hello_done = TLSRecord(version=self.tls_version) / TLSHandshake(type=TLSHandshakeType.SERVER_HELLO_DONE)
        self.tlssock.sendall(server_hello_done)
    
    @ATMT.state()
    @hookable
    def SERVER_HELLO_DONE_SENT(self):
        pass
    
    @ATMT.condition(SERVER_HELLO_DONE_SENT)
    @hookable
    def recv_client_key_exchange(self):
        p = self.tlssock.recvall()
        if self.debug_level >= 1:
            p.show()
        if not p.haslayer(TLSClientKeyExchange):
            raise self.ERROR(p)
        raise self.CLIENT_KEY_EXCHANGE_RECV()
    
    @ATMT.state()
    @hookable
    def CLIENT_KEY_EXCHANGE_RECV(self):
        raise self.CLIENT_CHANGE_CIPHERSPEC_RECV()
    
    @ATMT.state()
    @hookable
    def CLIENT_CHANGE_CIPHERSPEC_RECV(self):
        raise self.CLIENT_FINISH_RECV()
    
    @ATMT.state()
    @hookable
    def CLIENT_FINISH_RECV(self):
        pass
    
    @ATMT.condition(CLIENT_FINISH_RECV)
    @hookable
    def send_server_key_exchange(self):
        raise self.SERVER_KEY_EXCHANGE_SENT()
    
    @ATMT.action(send_server_key_exchange)
    @hookable
    def do_send_server_key_exchange(self):
        pass

    @ATMT.state()
    @hookable
    def SERVER_KEY_EXCHANGE_SENT(self):
        pass   
    
    @ATMT.condition(SERVER_KEY_EXCHANGE_SENT)
    @hookable
    def send_server_ccs(self):
        raise self.SERVER_CCS_SENT()

    @ATMT.action(send_server_ccs)
    @hookable
    def do_send_server_ccs(self):
        tls_version = self.tlssock.tls_ctx.params.negotiated.version
        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        self.tlssock.sendall(client_ccs)

    @ATMT.state()
    @hookable
    def SERVER_CCS_SENT(self):
        pass
 
    @ATMT.condition(SERVER_CCS_SENT)
    @hookable
    def send_server_finish(self):
        raise self.SERVER_FINISH_SENT()
    
    @ATMT.action(send_server_finish)
    @hookable
    def do_send_server_finish(self):
        #TODO: fix server finish calculation
        finished = to_raw(TLSFinished(), self.tlssock.tls_ctx)
        self.tlssock.sendall(finished)
    
    @ATMT.state()
    @hookable
    def SERVER_FINISH_SENT(self):
        pass
    
    @ATMT.condition(SERVER_FINISH_SENT)
    @hookable
    def recv_client_appdata(self):
        chunk_p = True
        p = SSL()
        self.debug(1,"polling in 5sec intervals until data arrives.")
        while chunk_p:
            chunk_p = self.tlssock.recvall(timeout=5)
            if (chunk_p.haslayer(SSL) and len(chunk_p[SSL].records)>0):
                p.records.append(chunk_p)
            else:
                if len(p[SSL].records)>0:
                    break
            
        if self.debug_level >= 1:
            p.show()
        if not (p.haslayer(TLSRecord) and p[TLSRecord].content_type==TLSContentType.APPLICATION_DATA):
            raise self.ERROR(p)
        raise self.CLIENT_APPDATA_RECV()
    
    @ATMT.state()
    @hookable
    def CLIENT_APPDATA_RECV(self):
        pass
    
    @ATMT.condition(CLIENT_APPDATA_RECV)
    @hookable
    def send_server_appdata(self):
        raise self.SERVER_APPDATA_SENT()
    
    @ATMT.action(send_server_appdata)
    @hookable
    def do_send_server_appdata(self):
        self.tlssock.sendall(to_raw(TLSPlaintext(data=self.response), self.tlssock.tls_ctx))
    
    @ATMT.state()
    @hookable
    def SERVER_APPDATA_SENT(self):
        raise self.END()
    
    # GENERIC ERROR - print received data if available
    @ATMT.state(error=1)
    @hookable
    def ERROR(self, p=None):
        if p and self.debug_level >= 1:
            p.show()
        return
    
    # GENERIC END - return server's response
    @ATMT.state(final=1)
    @hookable
    def END(self):
        self.tlssock.sendall(to_raw(TLSAlert(level=TLSAlertLevel.WARNING, description=TLSAlertDescription.CLOSE_NOTIFY), self.tlssock.tls_ctx))
