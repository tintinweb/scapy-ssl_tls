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
    from scapy_ssl_tls.ssl_tls_automata import TLSClientAutomata
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls_automata import TLSClientAutomata
    from scapy.layers.ssl_tls import *

if __name__ == '__main__':
    #conf.prog.dot = r'"path_to_graphviz/dot"'
    logging.basicConfig(level=logging.DEBUG)
    log_interactive.setLevel(1)

    if len(sys.argv) > 2:
        target = (sys.argv[1], int(sys.argv[2]))
    else:
        target = ("127.0.0.1", 8443)

    TLSClientAutomata.graph()

    auto_cli = TLSClientAutomata(debug=9,
                                 target=target,
                                 tls_version="TLS_1_1",
                                 cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA,
                                                TLSCipherSuite.RSA_WITH_RC4_128_SHA,
                                                TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA,
                                                TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA],
                                 request="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n")

    logger.debug("registered states: %s" % auto_cli.states)   # all registered states
    logger.debug("registered actions: %s" % auto_cli.actions)  # all registered actions
    logger.debug("pkt-to-state-mapping: %s" % auto_cli.STATES)  # mapped pkts to states
    logger.debug("pkt-to-action-mapping: %s" % auto_cli.ACTIONS)  # mapped pkts to actions

    # uncomment next lines to hook into the 'send_server_hello' condition.
    '''
    def jump_to_random_state(*args, **kwargs):
        import random
        next_state = random.choice(auto_cli.states.keys())
        raw_input(" **** -------------> override state, random pick: %s"%next_state)
        raise getattr(auto_cli,next_state)()

    auto_cli.register_callback(auto_cli.ACTIONS[TLSFinished], jump_to_random_state)
    '''
    print (auto_cli.run())
