# -*- coding: utf-8 -*-

from __future__ import division, print_function


try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls.ssl_tls_keystore import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

from Cryptodome.Hash import SHA

cipher = TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))

p = 31087337795061487877547416545715496334920954980132212151448781444321393445568157959166911302972918628838917381555939620290244963511997037011253946065678925033455872043721454426215650798450188675325621498188688302603627388365642425546473761584899398546726625631228589029183157123265299738241899897560139599077166257814263354432724020387267456594044458497157226037520021564951601668256091905149808373739011153824316842260356584928931097012930709279713696588076097146536216639697002502410139891180002231258705541413293860269631209702305813614701588402302998104362562812340366960005570331931340105075488237470969553357627
g = 2
# static keys, useful for debugging
# pub = 2125871996267512758440937716206512603621103725733128853670023276750359056929109977990923107335220374712970249769257853919772721992342930374089843069429228617116883876991043599792187305648967180918660248725801884477922844727389080588299774761427867334311611962769350758110650257157252429111266015137207279689987770168978149373710065109528843320177300785766805047155044366661677629480554155956075340869804965591554119959126464259393655871350672716415116740987826238924783679148503742326642773811919219418260151082333715095160084656660971123406821706132259138309787699569778331383585702671923320155407071017233617787829
# priv = 92962456013500211399866345346236345288428506357375060372460455212427921256133


def main():
    host = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("127.0.0.1", 8443)
    if len(sys.argv) == 4:
        server_cert = server_key = sys.argv[3]
    elif len(sys.argv) == 5:
        server_cert = sys.argv[3]
        server_key = sys.argv[4]
    else:
        server_cert = os.path.join(basedir, "tests/integration/keys/cert.der")
        server_key = os.path.join(basedir, "tests/integration/keys/key.pem")

    with open(server_cert, "rb") as f:
            cert = f.read()
    certificates = TLSCertificate(data=cert)

    with TLSSocket(client=False) as tls_socket:
        tls_ctx = tls_socket.tls_ctx
        tls_ctx.server_ctx.load_rsa_keys_from_file(os.path.join(basedir, server_key))

        try:
            tls_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            tls_socket.bind(host)
            tls_socket.listen(1)
        except socket.error as se:
            print("Failed to bind server: %s" % (host,), file=sys.stderr)
        else:
            try:
                client_socket, _ = tls_socket.accept()
                client_hello = client_socket.recvall()
                version = client_hello[TLSHandshakes].handshakes[0][TLSClientHello].version

                server_hello = TLSRecord(version=version) / \
                               TLSHandshakes(handshakes=[TLSHandshake() / TLSServerHello(version=version, cipher_suite=cipher),
                                                         TLSHandshake() / TLSCertificateList() / TLS10Certificate(certificates=certificates)])

                client_socket.do_round_trip(server_hello, recv=False)

                # Generate a fresh keypair and install them in server context
                tls_ctx.server_ctx.kex_keystore = DHKeyStore.new_keypair(g, p)
                dhe_ske = tls_ctx.get_server_dhe_ske(digest=SHA)
                # Make sure to set "scheme_type" to the right sig alg. No logic in get_server_dhe_ske to do so now
                dhe_ske.scheme_type = TLSSignatureScheme.RSA_PKCS1_SHA1
                ske = TLSRecord(version=version) / \
                               TLSHandshakes(handshakes=[TLSHandshake() / TLSServerKeyExchange() / dhe_ske,
                                                         TLSHandshake(type=TLSHandshakeType.SERVER_HELLO_DONE)])
                cke = client_socket.do_round_trip(ske)
                cke.show()

                client_socket.do_round_trip(TLSRecord(version=version) /
                                            TLSChangeCipherSpec(), recv=False)
                client_socket.do_round_trip(TLSHandshakes(handshakes=[TLSHandshake() /
                                                                      TLSFinished(data=client_socket.tls_ctx.get_verify_data())]), recv=False)

                client_socket.do_round_trip(TLSPlaintext(data="It works!\n"), recv=False)
                client_socket.do_round_trip(TLSAlert(), recv=False)
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            finally:
                print(client_socket.tls_ctx)

if __name__ == "__main__":
    main()
