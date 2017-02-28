#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import sys

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls.ssl_tls_crypto import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.layers.ssl_tls_crypto import *


index = 0


def modify_padding(crypto_container):
    padding = crypto_container.padding
    crypto_container.padding = "%s\xff%s" % (padding[:index], padding[index + 1:])
    return crypto_container


def modify_mac(crypto_container):
    mac = crypto_container.mac
    crypto_container.mac = "%s\xff%s" % (mac[:index], mac[index + 1:])
    return crypto_container


def send_application_data(server, cipher_suite, data, hook):
    s = socket.socket()
    s.connect(server)
    tls_socket = TLSSocket(s, client=True)
    version = TLSVersion.TLS_1_0
    tls_do_handshake(tls_socket, version, cipher_suite)
    tls_socket.pre_encrypt_hook = hook
    tls_socket.sendall(TLSPlaintext(data=data))
    r = tls_socket.recvall()
    return r


def align_data_on_block_bounday(data, cipher_suite, pad_char="a"):
    data_len = len(data)
    block_len = TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size
    mac_len = TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size
    junk_len = block_len - ((data_len + mac_len) % block_len)
    return "%s%s" % (data, pad_char * junk_len)


def test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding):
    error_msg = ""
    try:
        resp = send_application_data(server, cipher_suite, block_aligned_request, modify_padding)
        if len(resp.records) == 0:
            error_msg = "Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert"
        elif resp.haslayer(TLSAlert) and resp[TLSAlert].description == TLSAlertDescription.BAD_RECORD_MAC:
            error_msg = "Server is not vulnerable"
        else:
            error_msg = "Server is probably vulnerable\n"
            error_msg += "If application data was displayed above, server is definitely vulnerable"
            resp.show()
    except socket.error:
        error_msg += "Connection reset by peer"
    return error_msg


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    cipher_suite = TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA

    request = "GET / HTTP/1.1\r\nHOST: %s\r\n\r\n" % server[0]
    block_aligned_request = align_data_on_block_bounday(request, cipher_suite)

    print("Testing all padding bytes")
    # Perform poodle 2 check
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size - 1):
        print("Modifying padding byte %d" % index)
        print(test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding))
        index += 1

    print("Testing all mac bytes")
    index = 0
    # Perform mac check
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size - 1):
        print("Modifying mac byte %d" % index)
        print(test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_mac))
        index += 1

    print("Test complete")
