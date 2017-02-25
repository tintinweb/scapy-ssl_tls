#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : <github.com/tintinweb/scapy-ssl_tls>

import socket
import functools

from ssl_tls import *
from ssl_tls_crypto import *

from scapy.automaton import Automaton, ATMT


def hookable(f):
    @functools.wraps(f)
    def wrapped_f(*args, **kwargs):
        if args and isinstance(args[0], Automaton):
            obj = args[0]
            cb_f = obj.callbacks.get(f.__name__.rsplit("_wrapper", 1)[0], None)
            if cb_f:
                obj.debug(1, "*** CALLBACK *** calling '%s' -> %s" % (f.__name__, cb_f))
                return cb_f(*args, **kwargs)
        return f(*args, **kwargs)

    if f.atmt_type == ATMT.CONDITION:
        '''tin: ugly hack Part I
                its not possible to easily decorate ATMT.Conditions
                without breaking ATMT.graph() as the graph method relies on
                 inspecting the caller functions code :/
                  see scapy\automaton.py::graph()
                    for n in f.func_code.co_names+f.func_code.co_consts
                therefore we're only saving the wrapper as an attribute to that
                 function and have ATMT.run() cleanup the ATMT.conditions map
                 to use hookable(condition) that is stored in f.wrapper_f instead
                 of the unwrapped function.
                this way, ATMT.graph() works fine as long as it is called before
                ATMT.run()
        '''
        f.wrapper_f = wrapped_f
        return f
    else:
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

    def __init__(self, *args, **kwargs):
        self.callbacks = {}  # fname:func
        # trickery: disable unneeded automata internal sockets by faking a null-obj
        kwargs['ll'] = type('obj', (object,), {})
        kwargs['recvsock'] = kwargs['ll']
        Automaton.__init__(self, *args, **kwargs)
        self.STATES = {TLSClientHello: 'CLIENT_HELLO_SENT',
                       TLSServerHello: 'SERVER_HELLO_RECV',
                       TLSCertificate: 'SERVER_HELLO_RECV',
                       TLSCertificateList: 'SERVER_HELLO_RECV',
                       TLSServerHelloDone: 'SERVER_HELLO_RECV',
                       TLSFinished: 'CLIENT_FINISH_SENT',
                       TLSChangeCipherSpec: 'CLIENT_CHANGE_CIPHERSPEC_SENT',
                       TLSClientKeyExchange: 'CLIENT_KEY_EXCHANGE_SENT',
                       # TLSServerKeyExchange: 'xxx',
                       TLSPlaintext: 'CLIENT_APPDATA_SENT',
                       TLSDecryptablePacket: 'CLIENT_APPDATA_SENT',
                       }
        self.ACTIONS = {TLSClientHello: 'send_client_hello',
                        TLSServerHello: 'recv_server_hello',
                        TLSCertificate: 'recv_server_hello',
                        TLSCertificateList: 'recv_server_hello',
                        TLSServerHelloDone: 'recv_server_hello',
                        TLSFinished: 'send_client_finish',
                        TLSChangeCipherSpec: 'send_client_change_cipher_spec',
                        TLSClientKeyExchange: 'send_client_key_exchange',
                        # TLSServerKeyExchange: 'xxx',
                        TLSPlaintext: 'send_client_appdata',
                        TLSDecryptablePacket: 'send_client_appdata',
                        }

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

    def register_callback(self, fname, f):
        self.debug(1, "register callback: %s - %s" % (fname, repr(f)))
        self.callbacks[fname] = f

    def run(self, *args, **kwargs):
        """tin: ugly hack Part II:
                fix {state:condition_funcs} map to use hookable(f) instead of f
        """
        for name in self.conditions:
            self.conditions[name] = [getattr(cf, 'wrapper_f', cf) for cf in self.conditions[name]]
        return Automaton.run(self, *args, **kwargs)

    # GENERIC BEGIN
    @hookable
    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    # 1) check if already connected and connect if not
    @hookable
    @ATMT.condition(BEGIN, prio=1)
    def is_connected(self):
        if self.tlssock:
            raise self.CONNECTED()

    @hookable
    @ATMT.condition(BEGIN, prio=2)
    def not_connected(self):
        if not self.tlssock:
            raise self.CONNECTED()

    @hookable
    @ATMT.action(not_connected)
    def do_connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.target)
        self.debug(1, "connected")
        self.tlssock = TLSSocket(sock, client=True)

    @hookable
    @ATMT.state()
    def CONNECTED(self):
        pass

    # 2) send client hello
    @hookable
    @ATMT.condition(CONNECTED)
    def send_client_hello(self):
        raise self.CLIENT_HELLO_SENT()

    @hookable
    @ATMT.action(send_client_hello)
    def do_send_client_hello(self):
        client_hello = TLSRecord(version=self.tls_version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSClientHello(version=self.tls_version,
                                                                compression_methods=[ TLSCompressionMethod.NULL,],
                                                                cipher_suites=self.cipher_suites)])
        self.tlssock.sendall(client_hello)

    @hookable
    @ATMT.state()
    def CLIENT_HELLO_SENT(self):
        pass

    # 3) recv for server hello
    @hookable
    @ATMT.condition(CLIENT_HELLO_SENT)
    def recv_server_hello(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if not p.haslayer(TLSServerHello):
            raise self.ERROR(p)
        self.debug(
            10,
            "CIPHER: %s" %
            TLS_CIPHER_SUITES.get(
                p[TLSServerHello].cipher_suite,
                p[TLSServerHello].cipher_suite))
        raise self.SERVER_HELLO_RECV()

    @hookable
    @ATMT.state()
    def SERVER_HELLO_RECV(self):
        pass

    # 4) send client key exchange + CCS + finished
    @hookable
    @ATMT.condition(SERVER_HELLO_RECV)
    def send_client_key_exchange(self):
        raise self.CLIENT_KEY_EXCHANGE_SENT()

    @hookable
    @ATMT.action(send_client_key_exchange)
    def do_send_client_key_exchange(self):
        tls_version = self.tlssock.tls_ctx.negotiated.version
        client_key_exchange = TLSRecord(version=tls_version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                       self.tlssock.tls_ctx.get_client_kex_data()])
        self.tlssock.sendall(client_key_exchange)

    @hookable
    @ATMT.state()
    def CLIENT_KEY_EXCHANGE_SENT(self):
        pass

    @hookable
    @ATMT.condition(CLIENT_KEY_EXCHANGE_SENT)
    def send_client_change_cipher_spec(self):
        tls_version = self.tlssock.tls_ctx.negotiated.version
        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        self.tlssock.sendall(client_ccs)
        raise self.CLIENT_CHANGE_CIPHERSPEC_SENT()

    @hookable
    @ATMT.state()
    def CLIENT_CHANGE_CIPHERSPEC_SENT(self):
        pass

    @hookable
    @ATMT.condition(CLIENT_CHANGE_CIPHERSPEC_SENT)
    def send_client_finish(self):
        self.tlssock.sendall( TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=self.tlssock.tls_ctx.get_verify_data())]))
        raise self.CLIENT_FINISH_SENT()

    @hookable
    @ATMT.state()
    def CLIENT_FINISH_SENT(self):
        pass

    # 5) recv. server finished (not checking for CCS atm)
    @hookable
    @ATMT.condition(CLIENT_FINISH_SENT)
    def recv_server_finish(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if not (p.haslayer(TLSFinished) or (p.haslayer(TLSPlaintext) and SSL(
                str(TLSRecord(content_type='handshake') / p[TLSPlaintext].data)).haslayer(TLSFinished))):
            raise self.ERROR(p)
        raise self.SERVER_FINISH_RECV()

    @hookable
    @ATMT.state()
    def SERVER_FINISH_RECV(self):
        pass

    # 6) send application data
    @hookable
    @ATMT.condition(SERVER_FINISH_RECV)
    def send_client_appdata(self):
        raise self.CLIENT_APPDATA_SENT()

    @hookable
    @ATMT.action(recv_server_finish)
    def do_send_client_appdata(self):
        self.tlssock.sendall(TLSPlaintext(data=self.request))

    @hookable
    @ATMT.state()
    def CLIENT_APPDATA_SENT(self):
        pass

    # 7) receive application data
    @hookable
    @ATMT.condition(CLIENT_APPDATA_SENT)
    def recv_server_appdata(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if not (p.haslayer(TLSRecord) and p[TLSRecord].content_type == TLSContentType.APPLICATION_DATA):
            raise self.ERROR(p)
        raise self.SERVER_APPDATA_RECV(p)

    @hookable
    @ATMT.state()
    def SERVER_APPDATA_RECV(self, p=None):
        raise self.END(p)

    # GENERIC ERROR - print received data if available
    @hookable
    @ATMT.state(error=1)
    def ERROR(self, p=None):
        if p and self.debug_level >= 1:
            p.show()
        return

    # GENERIC END - return server's response
    @hookable
    @ATMT.state(final=1)
    def END(self, p=None):
        try:
            return ''.join(pkt[TLSPlaintext].data for pkt in p.records)
        except AttributeError:
            return p


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
        self.callbacks = {}  # fname:func
        # trickery: disable unneeded automata internal sockets by faking a null-obj
        kwargs['ll'] = type('obj', (object,), {})
        kwargs['recvsock'] = kwargs['ll']
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
        self.ACTIONS = {TLSClientHello: 'recv_client_hello',
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
            self.dercert = ''.join(
                line for line in pemo[key_pk].get("full").strip().split("\n") if not "-" in line).decode("base64")
            break
        self.debug(1, "parse_args - done")

    def register_callback(self, fname, f):
        self.debug(1, "register callback: %s - %s" % (fname, repr(f)))
        self.callbacks[fname] = f

    def run(self, *args, **kwargs):
        """tin: ugly hack Part II:
                fix {state:condition_funcs} map to use hookable(f) instead of f
        """
        for name in self.conditions:
            self.conditions[name] = [getattr(cf, 'wrapper_f', cf) for cf in self.conditions[name]]
        return Automaton.run(self, *args, **kwargs)

    # GENERIC BEGIN
    @hookable
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.debug(1, "BEGIN")

    @hookable
    @ATMT.condition(BEGIN)
    def listen(self):
        raise self.WAIT_FOR_CLIENT_CONNECTION()

    @hookable
    @ATMT.action(listen)
    def do_bind(self):
        self.debug(1, "dobind %s " % repr(self.bind))
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.srv_tls_sock = TLSSocket(self.srv_sock, client=False)
        self.srv_tls_sock.bind(self.bind)
        self.srv_tls_sock.listen(1)

        pemo = pem_get_objects(self.pemkey)
        for key_pk in (k for k in pemo.keys() if "PRIVATE" in k.upper()):
            self.srv_tls_sock.tls_ctx.server_ctx.asym_keystore = tlsk.RSAKeystore.from_private(pemo[key_pk].get("full"))
            break

    @hookable
    @ATMT.state()
    def WAIT_FOR_CLIENT_CONNECTION(self):
        self.debug(1, "accept")
        self.tlssock, self.peer = self.srv_tls_sock.accept()
        self.debug(1, "new connection: %s" % repr(self.peer))

    @hookable
    @ATMT.condition(WAIT_FOR_CLIENT_CONNECTION)
    def recv_client_hello(self):
        p = self.tlssock.recvall(timeout=self.timeout)
        if self.debug_level >= 1:
            p.show()
        if not p.haslayer(TLSClientHello):
            raise self.ERROR(p)
        self.tls_version = p[TLSClientHello].version
        raise self.CLIENT_HELLO_RECV()

    @hookable
    @ATMT.state()
    def CLIENT_HELLO_RECV(self):
        pass

    @ATMT.condition(CLIENT_HELLO_RECV)
    def send_server_hello(self):
        raise self.SERVER_HELLO_SENT()

    @hookable
    @ATMT.action(send_server_hello)
    def do_send_server_hello(self):
        server_hello = TLSRecord(version=self.tls_version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSServerHello(version=self.tls_version,
                                                                compression_method=TLSCompressionMethod.NULL,
                                                                cipher_suite=self.cipher_suite)])
        server_hello.show()
        self.tlssock.sendall(server_hello)

    @hookable
    @ATMT.state()
    def SERVER_HELLO_SENT(self):
        pass

    @hookable
    @ATMT.condition(SERVER_HELLO_SENT)
    def send_server_certificates(self):
        raise self.SERVER_CERTIFICATES_SENT()

    @hookable
    @ATMT.action(send_server_certificates)
    def do_send_server_certificates(self):
        if self.tls_version == "TLS_1_3":
            cls_cert = TLS13Certificate
        else:
            cls_cert = TLS10Certificate

        server_certificates = TLSRecord(version=self.tls_version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        TLSCertificateList() / cls_cert(certificates=[TLSCertificate(data=x509.X509Cert(self.dercert))])])

        server_certificates.show()
        self.tlssock.sendall(server_certificates)

    @hookable
    @ATMT.state()
    def SERVER_CERTIFICATES_SENT(self):
        pass

    @hookable
    @ATMT.condition(SERVER_CERTIFICATES_SENT)
    def send_server_hello_done(self):
        raise self.SERVER_HELLO_DONE_SENT()

    @hookable
    @ATMT.action(send_server_hello_done)
    def do_send_server_hello_done(self):
        server_hello_done = TLSRecord(version=self.tls_version) / \
                            TLSHandshakes(handshakes=[TLSHandshake() /
                                                      TLSServerHelloDone()])
        self.tlssock.sendall(server_hello_done)

    @hookable
    @ATMT.state()
    def SERVER_HELLO_DONE_SENT(self):
        pass

    @hookable
    @ATMT.condition(SERVER_HELLO_DONE_SENT)
    def recv_client_key_exchange(self):
        p = self.tlssock.recvall()
        if self.debug_level >= 1:
            p.show()
        if not p.haslayer(TLSClientKeyExchange):
            raise self.ERROR(p)
        raise self.CLIENT_KEY_EXCHANGE_RECV()

    @hookable
    @ATMT.state()
    def CLIENT_KEY_EXCHANGE_RECV(self):
        raise self.CLIENT_CHANGE_CIPHERSPEC_RECV()

    @hookable
    @ATMT.state()
    def CLIENT_CHANGE_CIPHERSPEC_RECV(self):
        raise self.CLIENT_FINISH_RECV()

    @hookable
    @ATMT.state()
    def CLIENT_FINISH_RECV(self):
        pass

    @hookable
    @ATMT.condition(CLIENT_FINISH_RECV)
    def send_server_key_exchange(self):
        raise self.SERVER_KEY_EXCHANGE_SENT()

    @hookable
    @ATMT.action(send_server_key_exchange)
    def do_send_server_key_exchange(self):
        pass

    @hookable
    @ATMT.state()
    def SERVER_KEY_EXCHANGE_SENT(self):
        pass

    @hookable
    @ATMT.condition(SERVER_KEY_EXCHANGE_SENT)
    def send_server_ccs(self):
        raise self.SERVER_CCS_SENT()

    @hookable
    @ATMT.action(send_server_ccs)
    def do_send_server_ccs(self):
        tls_version = self.tlssock.tls_ctx.negotiated.version
        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        self.tlssock.sendall(client_ccs)

    @hookable
    @ATMT.state()
    def SERVER_CCS_SENT(self):
        pass

    @hookable
    @ATMT.condition(SERVER_CCS_SENT)
    def send_server_finish(self):
        raise self.SERVER_FINISH_SENT()

    @hookable
    @ATMT.action(send_server_finish)
    def do_send_server_finish(self):
        # TODO: fix server finish calculation
        self.tlssock.sendall( TLSHandshakes(handshakes=[TLSHandshake() / TLSFinished(data=self.tlssock.tls_ctx.get_verify_data())]))

    @hookable
    @ATMT.state()
    def SERVER_FINISH_SENT(self):
        pass

    @hookable
    @ATMT.condition(SERVER_FINISH_SENT)
    def recv_client_appdata(self):
        chunk_p = True
        p = SSL()
        self.debug(1, "polling in 5sec intervals until data arrives.")
        while chunk_p:
            chunk_p = self.tlssock.recvall(timeout=5)
            if chunk_p.haslayer(SSL) and len(chunk_p[SSL].records) > 0:
                p.records.append(chunk_p)
            else:
                if len(p[SSL].records) > 0:
                    break

        if self.debug_level >= 1:
            p.show()
        if not (p.haslayer(TLSRecord) and p[TLSRecord].content_type == TLSContentType.APPLICATION_DATA):
            raise self.ERROR(p)
        raise self.CLIENT_APPDATA_RECV()

    @hookable
    @ATMT.state()
    def CLIENT_APPDATA_RECV(self):
        pass

    @hookable
    @ATMT.condition(CLIENT_APPDATA_RECV)
    def send_server_appdata(self):
        raise self.SERVER_APPDATA_SENT()

    @hookable
    @ATMT.action(send_server_appdata)
    def do_send_server_appdata(self):
        self.tlssock.sendall(TLSPlaintext(data=self.response))

    @hookable
    @ATMT.state()
    def SERVER_APPDATA_SENT(self):
        raise self.END()

    # GENERIC ERROR - print received data if available
    @hookable
    @ATMT.state(error=1)
    def ERROR(self, p=None):
        if p and self.debug_level >= 1:
            p.show()
        return

    # GENERIC END - return server's response
    @hookable
    @ATMT.state(final=1)
    def END(self):
        self.tlssock.sendall(
                TLSAlert(
                    level=TLSAlertLevel.WARNING,
                    description=TLSAlertDescription.CLOSE_NOTIFY))
