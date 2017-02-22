#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

from __future__ import print_function
import sys
import logging
logger = logging.getLogger(__name__)

from scapy.all import conf, log_interactive

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls_automata import TLSServerAutomata
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls_automata import TLSServerAutomata
    from scapy.layers.ssl_tls import *

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))

if __name__ == '__main__':
    #conf.prog.dot = r'"path_to_graphviz/dot"'
    logging.basicConfig(level=logging.DEBUG)
    log_interactive.setLevel(1)

    if len(sys.argv) > 2:
        target = (sys.argv[1], int(sys.argv[2]))
    else:
        target = ("127.0.0.1", 8443)

    server_pem = sys.argv[3] if len(sys.argv) > 3 else os.path.join(basedir,"tests/files/openssl_1_0_1_f_server.pem")

    TLSServerAutomata.graph()

    logger.info("using certificate/keyfile: %s" % server_pem)
    with open(server_pem, 'r') as f:
        pemcert = f.read()
    auto_srv = TLSServerAutomata(debug=9,
                                 bind=target,
                                 pemcert=pemcert,
                                 cipher_suite=TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                                 response="HTTP/1.1 200 OK\r\n\r\n")

    logger.debug("registered states: %s" % auto_srv.states)   # all registered states
    logger.debug("registered actions: %s" % auto_srv.actions)  # all registered actions
    logger.debug("pkt-to-state-mapping: %s" % auto_srv.STATES)  # mapped pkts to states
    logger.debug("pkt-to-action-mapping: %s" % auto_srv.ACTIONS)  # mapped pkts to actions

    # uncomment next line to hook into the 'send_server_hello' condition.
    '''
    def jump_to_server_hello_done(*args, **kwargs):
        raw_input(" **** -------------> override state, directly jump to SERVER_CERTIFICATES_SENT aka. SERVER_HELLO_DONE")
        raise auto_srv.SERVER_CERTIFICATES_SENT()

    def jump_to_random_state(*args, **kwargs):
        import random
        next_state = random.choice(auto_srv.states.keys())
        raw_input(" **** -------------> override state, random pick: %s"%next_state)
        raise getattr(auto_srv,next_state)()

    def jump_to_bla(*args, **kwargs):
        raise auto_srv.WAIT_FOR_CLIENT_CONNECTION()

    auto_srv.register_callback(auto_srv.ACTIONS[TLSFinished], jump_to_server_hello_done)
    auto_srv.register_callback(auto_srv.ACTIONS[TLSFinished], jump_to_random_state)
    '''
    print (auto_srv.run())
