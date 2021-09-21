#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function
import sys
import binascii
from struct import *

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls.ssl_tls_crypto import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.layers.ssl_tls_crypto import *

'''
To run this test you need to
- install scapy
- install scapy-ssl_tls (https://github.com/tintinweb/scapy-ssl_tls)
- move this file to [path to scapy-ssl_tls]/scapy-ssl_tls/examples
'''

indexpad = 0
indexmac = 0
incpad = 0
incpadlgth = 0
incmac = 0
verbose = 5


def modify_padding(crypto_container):
    '''
    function modifying the crypto. padding
    modify padding byte #indexpad with byte incpad
    '''
    padding = crypto_container.padding
    if verbose > 10:
        print('old pad', binascii.hexlify(bytearray(crypto_container.padding)))
    crypto_container.padding = ("%s" + chr(incpad) + "%s") % (padding[:indexpad], padding[indexpad + 1:])
    x = bytearray(crypto_container.padding)
    if verbose > 10:
        print('iv', binascii.hexlify(bytearray(crypto_container.explicit_iv)))
        print('mac', binascii.hexlify(bytearray(crypto_container.mac)))
        print('pad', binascii.hexlify(bytearray(crypto_container.padding)))
        print('pln', binascii.hexlify(bytearray(crypto_container.padding_len)))
    return crypto_container


def modify_mac(crypto_container):
    '''
    function modifying the crypto. mac
    modify mac byte #indexmac with byte #incmac
    '''
    # print("--- modify_mac")
    mac = crypto_container.mac
    if verbose > 10:
        print('old mac', binascii.hexlify(bytearray(crypto_container.mac)))
    crypto_container.mac = ("%s" + chr(incmac) + "%s") % (mac[:indexmac], mac[indexmac + 1:])

    if verbose > 10:
        print('iv', binascii.hexlify(bytearray(crypto_container.explicit_iv)))
        print('mac', binascii.hexlify(bytearray(crypto_container.mac)))
        print('pad', binascii.hexlify(bytearray(crypto_container.padding)))
        print('pln', binascii.hexlify(bytearray(crypto_container.padding_len)))
    return crypto_container


def modify_macpad(crypto_container):
    '''
    function modifying the crypto. padding and mac
    modify padding byte #indexpad with byte #incpad
    modify mac byte #indexmac with byte incmac
    '''
    # print("--- modify_mac")
    padding = crypto_container.padding
    mac = crypto_container.mac
    if verbose > 10:
        print('old pad', binascii.hexlify(bytearray(crypto_container.padding)))
        print('old mac', binascii.hexlify(bytearray(crypto_container.mac)))
    crypto_container.padding = ("%s" + chr(incpad) + "%s") % (padding[:indexpad], padding[indexpad + 1:])
    crypto_container.mac = ("%s" + chr(incmac) + "%s") % (mac[:indexmac], mac[indexmac + 1:])
    x = bytearray(crypto_container.mac)
    if verbose > 10:
        print('iv', binascii.hexlify(bytearray(crypto_container.explicit_iv)))
        print('mac', binascii.hexlify(bytearray(crypto_container.mac)))
        print('pad', binascii.hexlify(bytearray(crypto_container.padding)))
        print('pln', binascii.hexlify(bytearray(crypto_container.padding_len)))
    return crypto_container


def modify_padding_length(crypto_container):
    '''
    function modifying the crypto. padding length
    modify padding length byte with byte incpadlgth
    this test should return the same result as an invalid mac
    '''
    # print("--- modify_padding_length")
    l = crypto_container.padding_len
    if verbose > 10:
        print('old pad len', binascii.hexlify(bytearray(crypto_container.padding_len)))
    crypto_container.padding_len = chr(incpadlgth)

    if verbose > 10:
        print('iv', binascii.hexlify(bytearray(crypto_container.explicit_iv)))
        print('mac', binascii.hexlify(bytearray(crypto_container.mac)))
        print('pad', binascii.hexlify(bytearray(crypto_container.padding)))
        print('pln', binascii.hexlify(bytearray(crypto_container.padding_len)))
    return crypto_container


def send_application_data(server, cipher_suite, data, hook):
    # print("--- send_application_data")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(server)
    tls_socket = TLSSocket(s, client=True)
    version = TLSVersion.DTLS_1_0  # TLS_1_0
    dtls_do_handshake(tls_socket, version, cipher_suite)
    tls_socket.pre_encrypt_hook = hook
    tls_socket.sendall(DTLSRecord(version=version, sequence=1, epoch=1) / TLSPlaintext(data=data))

    resp = []
    tls_socket._s.settimeout(1)
    try:
        # we expect to see here the timeout or the RST
        data = tls_socket._s.recv(8192)
        resp.append(data)
    except Exception as e:
        # print( "first response", e)
        # we expect to get here the TLS alert
        data = tls_socket._s.recv(8192)
        if data:
            resp.append(data)

    # we decode the packet
    record = TLS("".join(resp), ctx=tls_socket.tls_ctx, _origin=tls_socket._get_pkt_origin('in'))

    if verbose > 10:
        # we show the full packet
        record.show()

    return record


def align_data_on_block_boundary(data, cipher_suite, pad_char="a"):
    '''
    function takin as input the raw data, a padding character and the cipher suite used
    and outputing the data padded to fit the cipher suite specifications
    '''
    # print("--- align_data_on_block_boundary")
    data_len = len(data)
    block_len = TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size
    mac_len = TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size
    junk_len = block_len - ((data_len + mac_len) % block_len)
    return "%s%s" % (data, pad_char * junk_len)


def test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding):
    '''
    function describing in human language the result of the test
    '''
    # print("--- test_all_field_bytes")

    error_msg = ""
    try:
        resp = send_application_data(server, cipher_suite, block_aligned_request, modify_padding)
        if len(resp.records) == 0:
            error_msg = "Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert"  # most likely a RST
        elif resp.haslayer(DTLSRecord) and resp[DTLSRecord].content_type == TLSAlertDescription.BAD_RECORD_MAC:
            error_msg = "bad_mac"  # badmac
        elif resp.haslayer(TLSAlert) and resp[TLSAlert].description == TLSAlertDescription.DECRYPT_ERROR:
            error_msg = "decrypt_error"
        else:
            #print(binascii.hexlify(bytearray(resp[Raw].load)))
            error_msg = "Server is probably vulnerable\n"  # different response, could be sign of a vulnerability or that the packet is correct and the page queried was not found
            error_msg += "If application data was displayed above, server is definitely vulnerable"
            #resp.show()
            if verbose > 10:
                resp.show()  # show dubious packet
    except Exception as e:
        error_msg = e  # Timeouts will appear here
    return error_msg


if __name__ == "__main__":
    '''
    main function to launch all of the tests
    by default we test:
    - with and without app data
    -- incorrect padding byte
    -- incorrect mac byte
    -- incorrect padding byte and mac byte
    the incorrect values are by default \x00, this can be changed at the top of the file
    to test all incorrect bytes, add loops to modify incmac, incpad and incpadlgth from 0 to 255
    '''

    server = ""
    host = None
    result = None
    if len(sys.argv) == 3:
        server = (sys.argv[1], int(sys.argv[2]))
        host = sys.argv[1]
    elif len(sys.argv) == 4:
        server = (sys.argv[1], int(sys.argv[2]))
        verbose = int(sys.argv[3])
        host = sys.argv[1]
    else:
        server = ("10.102.59.251", 4433)
    cipher_suite = TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA
    # cipher_suite = TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA
    #resfile = 'result_' + host + '.txt'
    # sys.stdout = open(resfile,'w')

    print("TLS Poodle: testing host", server, end='\t')

    ## Case with App Data
    print("\n\n\nTests with APPDATA ----------------------------------------------", end='\t')
    request = "GET / HTTP/1.1\r\nHOST: %s\r\n\r\n" % server[0]
    block_aligned_request = align_data_on_block_boundary(request, cipher_suite)
    '''
    print("\n\n\nTesting correct case", end =" ")
    errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, None)
    result = '\tPASSED\t'
    print(errmsg, result, end = '\t')
    '''
    indexpad = 0
    print("\n\n\nTesting all padding bytes", end=" ")
    # Perform poodle 2 check
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size - 1):
        print("\nModifying padding byte %d" % indexpad, end='\t')
        try:
            errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding)
            if (errmsg == 'Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert'):
                result = '\tPASSED\t'
            else:
                result = '\tFAILED\t'
            print(errmsg, result, end='\t')
        except Exception as e:
            print(e)
        indexpad += 1

    # incpadlgth = 0
    # print("\n\n\nTesting all padding length")
    # for i in range(0,256):
    #    print("\nModifying padding length with byte %d" % indexpadlgth) # modify_padding_length
    #    print(test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding_length))
    #    incpadlgth += 1

    indexmac = 0
    print("\n\n\nTesting all mac bytes", end='\t')
    # Perform mac check
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size - 1):
        print("\nModifying mac byte %d" % indexmac, end='\t')
        errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_mac)
        if (errmsg == 'Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert'):
            result = '\tPASSED\t'
        else:
            result = '\tFAILED\t'
        print(errmsg, result, end='\t')
        indexmac += 1

    indexmac = 0
    indexpad = 0
    print("\n\n\nTesting bad mac bad padding", end='\t')
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size - 1):
        indexmac = 0
        for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size - 1):
            print("\n\nModifying pad index %d" % indexpad, " and mac index %d" % indexmac, end='\t')
            errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_macpad)
            if (errmsg == 'Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert'):
                result = '\tPASSED\t'
            else:
                result = '\tFAILED\t'
            print(errmsg, result, end='\t')
            indexmac += 1
        indexpad += 1

    ## Case without App Data
    print("\n\n\nTests WITHOUT APPDATA----------------------------------------------", end='\t')
    request = ""
    block_aligned_request = request
    '''
    print("\n\n\nTesting correct case", end = '\t')
    errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, None)
    result = '\tPASSED\t'
    print(errmsg, result, end = '\t')
    '''
    indexpad = 0
    print("\n\n\nTesting all padding bytes", end='\t')
    # Perform poodle 2 check
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size - 1):
        print("\nModifying padding byte %d" % indexpad, end='\t')
        try:
            errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding)
            if (errmsg == 'Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert'):
                result = '\tPASSED\t'
            else:
                result = '\tFAILED\t'
            print(errmsg, result, end='\t')
        except Exception as e:
            print(e)
        indexpad += 1

    # incpadlgth = 0
    # print("\n\n\nTesting all padding length")
    # for i in range(0,256):
    #    print("\nModifying padding length %d" % indexpadlgth) # modify_padding_length
    #    print(test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_padding_length))
    #    incpadlgth += 1

    indexmac = 0
    print("\n\n\nTesting all mac bytes", end='\t')
    # Perform mac check
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size - 1):
        print("\nModifying mac byte %d" % indexmac, end='\t')
        errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_mac)
        if (errmsg == 'Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert'):
            result = '\tPASSED\t'
        else:
            result = '\tFAILED\t'
        print(errmsg, result, end='\t')
        indexmac += 1

    indexmac = 0
    indexpad = 0
    print("\n\n\nTesting bad mac bad padding", end='\t')
    for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["cipher"]["type"].block_size - 1):
        indexmac = 0
        for _ in range(0, TLSSecurityParameters.crypto_params[cipher_suite]["hash"]["type"].digest_size - 1):
            print("\n\nModifying pad index %d" % indexpad, " and mac index %d" % indexmac, end='\t')
            errmsg = test_all_field_bytes(server, cipher_suite, block_aligned_request, modify_macpad)
            if (errmsg == 'Server is not vulnerable, but implementation does not send a BAD_RECORD_MAC alert'):
                result = '\tPASSED\t'
            else:
                result = '\tFAILED\t'
            print(errmsg, result, end='\t')
            indexmac += 1
        indexpad += 1

    print("\n\nTest complete", end='\t')
    # fp.close()
