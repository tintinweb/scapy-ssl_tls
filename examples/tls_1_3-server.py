# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls.ssl_tls_crypto import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    from scapy.layers.ssl_tls_crypto import *

def main():
    err = 0
    
    if len(sys.argv) > 2:
        host = (sys.argv[1], int(sys.argv[2]))
    else:
        host = ("127.0.0.1", 8443)


    with open(os.path.join(basedir, "tests/integration/keys/cert.der"), "rb") as f:
        cert = f.read()
    certificates = TLSCertificateEntry(cert_data=cert)
    
    nist256 = ec_reg.get_curve(TLS_SUPPORTED_GROUPS[TLSSupportedGroup.SECP256R1])
    keypair = ec.make_keypair(nist256)
    ec_pub = tlsk.point_to_ansi_str(keypair.pub)
    
    version = tls.tls_draft_version(18)
    key_share = TLSExtension() / TLSExtKeyShare() / \
                TLSServerHelloKeyShare(server_share=TLSKeyShareEntry(named_group=TLSSupportedGroup.SECP256R1,
                                                                     key_exchange=ec_pub))
    named_groups = TLSExtension() / TLSExtSupportedGroups(named_group_list=[TLSSupportedGroup.SECP256R1,
                                                                            TLSSupportedGroup.SECP384R1,
                                                                            TLSSupportedGroup.SECP521R1])
    
    with TLSSocket(client=False) as tls_socket:
        # Setup certificate and key share
        tls_socket.tls_ctx.server_ctx.load_rsa_keys_from_file(os.path.join(basedir, "tests/integration/keys/key.pem"))
        tls_socket.tls_ctx.server_ctx.kex_keystore = tlsk.ECDHKeyStore.from_keypair(nist256, keypair)
        try:
            tls_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            tls_socket.bind(host)
            tls_socket.listen(1)
            client_socket, _ = tls_socket.accept()
        except socket.error as se:
            print("Failed to bind server: %s" % (host,), file=sys.stderr)
            err += 1
        else:
            try:
                r = client_socket.recvall()
                r.show()
    
                server_hello = TLSRecord() / \
                               TLSHandshakes(handshakes=[TLSHandshake() /
                                                         TLSServerHello(version=version,
                                                                        cipher_suite=TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                                                                        extensions=[key_share])])
                client_socket.sendall(server_hello)
                client_socket.sendall(TLSRecord() /
                                      TLSHandshakes(handshakes=[TLSHandshake() / TLSEncryptedExtensions(extensions=[named_groups]),
                                                                TLSHandshake() / TLSCertificateList() / TLS13Certificate(certificates=certificates)]))
                client_socket.sendall(TLSHandshakes(handshakes=[TLSHandshake() /
                                                                TLSCertificateVerify(alg=TLSSignatureScheme.RSA_PKCS1_SHA256,
                                                                                     sig=client_socket.tls_ctx.compute_server_cert_verify())]))
                r = client_socket.do_round_trip(TLSHandshakes(handshakes=[TLSHandshake() /
                                                                          TLSFinished(data=client_socket.tls_ctx.get_verify_data())]))
                r.show()
    
                client_socket.sendall(TLSPlaintext(data="It works!"))
                client_socket.sendall(TLSRecord() / TLSAlert())
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
                err +=1
            finally:
                print(client_socket.tls_ctx)
    return err

if __name__=="__main__":
    sys.exit(main())
