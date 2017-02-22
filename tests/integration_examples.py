#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Integration testsuite
    * quicktest examples: client, server, sniffer
"""
from __future__ import with_statement
from __future__ import print_function
import unittest
import socket
import time
import os

from helper import wait_for_server, wait_for_bind_to_become_ready, PopenProcess, PythonInterpreter, OpenSslClient, OpenSslServer

# global settings
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
EXAMPLES_CWD = os.path.join(basedir, "./examples")
BIND = ("127.0.0.1", 8443)
SERVER_PEM = os.path.join(basedir, "./tests/files/openssl_1_0_1_f_server.pem")
SERVER_DER_KEY_RSA = (os.path.join(basedir, "./tests/integration/keys/cert.der"), 
                      os.path.join(basedir, "./tests/integration/keys/key.pem"))
# client.py <ip> <port>
TEST_SCRIPT_AS_CLIENT = [ 'SCSV_fallback_test.py', 'client_hello_complex_invalid.py', 'client_hello_rsa.py',
                           'client_hello_twice.py', 'client_hello_valid.py', 'client_hello_valid_w_alpn.py',
                           'client_hello_with_session_ticket.py',
                           'full_rsa_connection_with_application_data.py', 'padding_and_mac_checks.py',
                           'sslv2_client_hello_valid.py', 'tls_client_automata.py']

EXTERNAL_SERVER = ("cloudflare.com", 443) # tls13
TEST_SCRIPT_AGAINST_EXTERNAL_SERVER = ['tls_1_3-client.py',]

class TestExampleClientsAgainstLocalOpenSsl(unittest.TestCase):
    """
    TLS client tests: client.py <ip> <port>
    
    test-cases will be created dynamically for similar looking testcases 
        listed in TEST_SCRIPT_AS_CLIENT
    """
    def setUp(self):
        self.bind = BIND
        wait_for_bind_to_become_ready(self.bind)
        self.tls_server = OpenSslServer(args=(self.bind, SERVER_PEM))
        wait_for_server(self.tls_server.bind)
        
    def tearDown(self):
        self.tls_server.kill()
        
    def test_security_scanner_client_mode(self):
        """
        USAGE: <mode> <host> <port> [starttls] [num_worker] [interface]
           mode     ... client | sniff
           starttls ... starttls keyword e.g. 'starttls\n' or 'ssl\n'

        """
        pid = PythonInterpreter("security_scanner.py", 
                                args=["client",]+list(self.bind), 
                                cwd=EXAMPLES_CWD)
        self.assertEqual(pid.getReturnCode(), 0)
        pid.kill()
    
    @unittest.skip("NOT YET IMPLEMENTED")
    def test_sessionctx_sniffer_pcap_mode(self):
        """
        USAGE: <host> <port> <inteface or pcap> <keyfile> <num pkts>

        python ../examples/sessionctx_sniffer.py 192.168.220.131 443 ../tests/files/RSA_WITH_AES_128_CBC_SHA.pcap ../tests/files/openssl_1_0_1_f_server.pem
        
        """
        raise NotImplementedError("NOT YET IMPLEMENTED")
        pid = PythonInterpreter("sessionctx_sniffer.py", 
                                args=["192.168.220.131", 443, 
                                      os.path.join(basedir,"./tests/files/RSA_WITH_AES_128_CBC_SHA.pcap"),
                                      os.path.join(basedir,"./tests/files/openssl_1_0_1_f_server.pem")],
                                cwd=EXAMPLES_CWD)
        self.assertEqual(pid.getReturnCode(), 0)
        pid.kill()

    @unittest.skip("NOT YET IMPLEMENTED")
    def test_client_rsa_mutual_auth(self):
        """
        does not seem to work right now - needs investigation
        #> openssl s_server -state -msg -cert scapy-ssl_tls/tests/integration/keys/scapy-tls-ca.crt.pem -key scapy-ssl_tls/tests/integration/keys/scapy-tls-ca.key.pem

        """
        raise NotImplementedError("NOT YET IMPLEMENTED")
        
"""
generate dynamic testcases in client mode
"""
def generator_client(target, args=[], cwd=None):
    """
    generates dynamic testcase
    """
    def test(self):
        pid = PythonInterpreter(target, args, cwd)
        self.assertEqual(pid.getReturnCode(), 0)
        pid.kill()
    return test

# add test-cases to test-class
for script in TEST_SCRIPT_AS_CLIENT:
    setattr(TestExampleClientsAgainstLocalOpenSsl, 
            "test_%s" % script.replace('.', '_'), 
            generator_client(script, BIND, EXAMPLES_CWD))

class TestExampleServerAgainstLocalOpenSslClient(unittest.TestCase):
    """
    TLS server tests: server.py <ip> <port> [<server.pem> or <cert.der><key.pem>]
    """

    def setUp(self):
        self.bind = BIND
        
    def server_testcase(self, target, args=[], cwd=None):
        # spawn server (example script)
        wait_for_bind_to_become_ready(tuple(args[:2]))
        server = PythonInterpreter(target, args, cwd)
        #wait_for_server(self.bind)
        # we cannot poll as this would mess up the server socket
        time.sleep(3)
        # connect with client (openssl)
        client = OpenSslClient(args=(self.bind))
        # wait for server to exit until client quits (getReturnCode waits until proc exits)
        client.stdin.write("It works!\r\n\r\n")
        self.assertEqual(server.getReturnCode(), 0)
        print ("server exit")
        print ("terminating client...")
        self.assertEqual(client.getReturnCode("Q\n"), 0)
        client.kill()
        server.kill()
        
    def test_server_rsa_py(self):
        self.server_testcase("server_rsa.py", 
                             args=list(BIND)+list(SERVER_DER_KEY_RSA), 
                             cwd=EXAMPLES_CWD)
        
    def test_tls_server_automata(self):
        self.server_testcase("tls_server_automata.py", 
                             args=list(BIND)+[SERVER_PEM], 
                             cwd=EXAMPLES_CWD)
        
    def test_cve_2014_3466(self):
        self.server_testcase("tls_server_automata.py", 
                             args=list(BIND)+[SERVER_PEM], 
                             cwd=EXAMPLES_CWD)

class TestExampleClientAgainstExternalServer(unittest.TestCase):
    """
    TLS client tests against external server: server.py <ip> <port>
    """

    def server_testcase(self, target, args=[], cwd=None):
        # spawn server (example script)
        server = PythonInterpreter(target, args, cwd)
        # we cannot poll as this would mess up the server socket
        self.assertEqual(client.getReturnCode("Q\n"), 0)
        client.kill()
        server.kill()

for script in TEST_SCRIPT_AGAINST_EXTERNAL_SERVER:
    setattr(TestExampleClientAgainstExternalServer,
            "test_%s" % script.replace('.', '_'),
            generator_client(script, EXTERNAL_SERVER, EXAMPLES_CWD))

class TestExampleSnifferWithOpenSslServerAndClient(unittest.TestCase):
    """
    TLS Sniffer tests:
    """
    def setUp(self):
        self.bind = BIND
        wait_for_bind_to_become_ready(self.bind)
        self.tls_server = OpenSslServer(args=(self.bind, SERVER_PEM))
        wait_for_server(self.tls_server.bind)
        
    def tearDown(self):
        self.tls_server.kill()
    
    @unittest.skip("NOT YET IMPLEMENTED") 
    def test_security_scanner_sniffer_mode(self):
        raise NotImplementedError("NOT YET IMPLEMENTED")
        return
    
    @unittest.skip("NOT YET IMPLEMENTED")
    def test_sessionctx_sniffer_lo(self):
        raise NotImplementedError("NOT YET IMPLEMENTED")
        """
        USAGE: <host> <port> <inteface or pcap> <keyfile> <num pkts>
        
        """
        sniffer = PythonInterpreter("sessionctx_sniffer.py", 
                                    args=list(self.bind)+["lo", SERVER_PEM, 10], 
                                    cwd=EXAMPLES_CWD)
        #wait_for_server(self.bind)
        # we cannot poll as this would mess up the server socket
        time.sleep(3)
        # connect with client (openssl)
        for _ in xrange(50):
            client = OpenSslClient(args=(self.bind))
            client.stdin.write("It works!\r\n\r\n")
            self.assertEqual(client.getReturnCode("Q\n"), 0)
            client.kill()
            if sniffer.pid.returncode:
                # sniffer exited (after processing 10 valid packets)
                break
        
        self.assertEqual(sniffer.getReturnCode(), 0)
        print ("server exit")
        print ("terminating client...")
        sniffer.kill()

if __name__ == '__main__':
    # todo remove_me - nosetestify me
    unittest.main()
