.. image:: https://travis-ci.org/tintinweb/scapy-ssl_tls.svg
    :target: https://travis-ci.org/tintinweb/scapy-ssl_tls

SSL/TLS layers for scapy the interactive packet manipulation tool.

Scapy-SSL/TLS
=============

SSL/TLS and DTLS layers and TLS utiltiy functions for
`Scapy <http://www.secdev.org/projects/scapy/>`_.

An offensive stack for SSLv2, SSLv3 (TLS), TLS, DTLS penetration testing
providing easy access to packet crafting, automatic dissection,
encryption, decryption, session tracking, basic TLS state machines,
automated handshakes, TLSSocket abstraction, cryptography containers,
predefined hooks, SSL sniffing including minimalistic PCAP stream
decryption (RSA\_WITH\_\*), fuzzing and security scanning
(*Renegotiation, Heartbleed, Poodle, Logjam/Freak, DROWN, various Buffer
overflows, ...*).

Compatibility
-------------

**!! v2.x breaks backwards compatibility to v1.2.x branch due to major interface refactoring introduced with tls1_3 support !!**

see `Release Notes <https://github.com/tintinweb/scapy-ssl_tls/releases>`_ 


Features
--------

-  Protocol Support
-  TLS 1.3 draft 18
-  TLS 1.2
-  TLS 1.1
-  TLS 1.0
-  SSLv3/TLS Records
-  SSLv2 Handshake
-  DTLS Records
-  TLS Session Context
-  Session Tracking
-  Key sniffing (master\_key, ...)
-  Client and Server support
-  Sniffer / PCAP processor and decryptor
-  State Machines
-  TLS Client Scapy Automata
-  TLS Server Scapy Automata

Installation
------------

Option 1: pip - download latest release from the python package index
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

::

    pip install scapy-ssl_tls

Option 2: from source
'''''''''''''''''''''

::

    pip install -r requirements.txt
    python setup.py install

Option 3: manual installation
'''''''''''''''''''''''''''''

1) install requirements from requirements.txt

2) locate *< scapy >* installation directory:
   ``python -c "import scapy; print scapy.__file__"``

3) copy scapy\_ssl\_tls/\* to *< scapy >*/layers/

4) modify *< scapy >*/config.py to autoload SSL/TLS

::

    @@ -373,3 +373,3 @@
    load_layers = ["l2", "inet", "dhcp", "dns", "dot11", "gprs", "hsrp", "inet6", "ir", "isakmp", "l2tp",
    -                   "mgcp", "mobileip", "netbios", "netflow", "ntp", "ppp", "radius", "rip", "rtp",
    +                   "mgcp", "mobileip", "netbios", "netflow", "ntp", "ppp", "radius", "rip", "rtp","ssl_tls",
                        "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp" ]



verify installation:
''''''''''''''''''''

::

    #> python
        >>> from scapy_ssl_tls.ssl_tls import TLS
        >>> TLS
        <class 'scapy_ssl_tls.ssl_tls.SSL'>
    #> scapy  # via site-packages
        >>> from scapy_ssl_tls.ssl_tls import TLS
        >>> TLS
        <class 'scapy_ssl_tls.ssl_tls.SSL'>
    #> scapy  # with layers autoloaded via config.py
        >>> SSL
        <class 'scapy.layers.ssl_tls.SSL'>
        >>> TLS
        <class 'scapy.layers.ssl_tls.SSL'>
        >>> TLSRecord
        <class 'scapy.layers.ssl_tls.TLSRecord'>

Troubleshooting
---------------

**Q:** ``sessionctx_sniffer.py`` does not seem to detect ``SSL/TLS`` or
does not show any sniffed ``SSL/TLS`` sessions.
**A:** This is problem caused by the import magic in
``sessionctx_sniffer.py`` where the example might mix up imports from
the projects directory with the ones installed with ``pip`` or via
``setup.py install``. Make sure to update to ``>=v1.2.3``, or run
``sessionctx_sniffer.py`` from a different directory, or uninstall
scapy-ssl\_tls to use it directly from the project directory, or remove
the ``from scapy_ssl_tls.ssl_tls import *`` import lines from the
example.
**Note:** This has been addressed with ``>=v1.2.3`` where the
system-wide import has preference.

**Q:** ``sessionctx_sniffer.py`` does not seem to dissect large
``SSL/TLS`` records properly.
**A:** In order to fully reconstruct *sniffed* ``SSL/TLS`` records one
needs to ``defragment`` the sniffed IP packets and ``reassemble`` them
to TCP segments. Since TCP Stream reassembly is not an easy task
(retransmissions, out-of-order segments, ...) - and therefore out of
scope for this project - the ``sessionctx_sniffer.py`` example
implements a very limited tcp stream reassembly algorithm that only
tries to reconstruct consecutive segments not taking into account any
type of flow-control (ordering, retransmissions, ...).

Examples
--------

Heartbleed Record
'''''''''''''''''

::

    ==============================================================================
    >>> (TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')).show()
    ###[ TLS Record ]###
      content_type= heartbeat
      version= TLS_1_1
      length= None
    ###[ TLS Extension HeartBeat ]###
         type= request
         length= 16383
         data= 'bleed...'
         padding= ''

Heartbleed Attack
'''''''''''''''''

::

    import scapy
    from scapy.layers.ssl_tls import *
    import socket

    target = ('target.local',443)

    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    p = TLSRecord(version="TLS_1_1")/TLSHandshake()/TLSClientHello(version="TLS_1_1")
    s.sendall(str(p))
    s.recv(8192)
    p = TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')
    s.sendall(str(p))
    resp = s.recv(8192)
    print "resp: %s"%repr(resp)
    s.close()

Dissect TLSClientHello (pcap)
'''''''''''''''''''''''''''''

::

    >>> rdpcap("a.cap")[3].show()
    ###[ Ethernet ]###
      dst= d0:ae:ec:c3:6e:d4
      src= f0:1f:af:1c:b6:01
      type= 0x800
    ###[ IP ]###
         version= 4L
         ihl= 5L
         tos= 0x0
         len= 257
         id= 12457
         flags= DF
         frag= 0L
         ttl= 128
         proto= tcp
         chksum= 0x5b97
         src= 192.168.2.45
         dst= 216.58.210.166
         \options\
    ###[ TCP ]###
            sport= 54988
            dport= https
            seq= 2403802801L
            ack= 3671968520L
            dataofs= 5L
            reserved= 0L
            flags= PA
            window= 64350
            chksum= 0x210e
            urgptr= 0
            options= []
    ###[ SSL/TLS ]###
               \records\
                |###[ TLS Record ]###
                |  content_type= handshake
                |  version= TLS_1_0
                |  length= 0xd4
                |###[ TLS Handshake ]###
                |     type= client_hello
                |     length= 0xd0
                |###[ TLS Client Hello ]###
                |        version= TLS_1_2
                |        gmt_unix_time= 3242904930L
                |        random_bytes= 'x"W\xe6\xfd\x97\xb7\xaf \xda\x12c\x8c\x07 o\xe3\th\xc3\xc1\xe0\xe3C\xe4\x00\xc6\xc7'
                |        session_id_length= 0x0
                |        session_id= ''
                |        cipher_suites_length= 0x28
                |        cipher_suites= ['ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'DHE_RSA_WITH_AES_128_GCM_SHA256', '0xcc14', '0xcc13', 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'ECDHE_RSA_WITH_AES_128_CBC_SHA', 'ECDHE_RSA_WITH_AES_256_CBC_SHA', 'ECDHE_ECDSA_WITH_RC4_128_SHA', 'ECDHE_RSA_WITH_RC4_128_SHA', 'DHE_RSA_WITH_AES_128_CBC_SHA', 'DHE_DSS_WITH_AES_128_CBC_SHA', 'DHE_RSA_WITH_AES_256_CBC_SHA', 'RSA_WITH_AES_128_GCM_SHA256', 'RSA_WITH_AES_128_CBC_SHA', 'RSA_WITH_AES_256_CBC_SHA', 'RSA_WITH_3DES_EDE_CBC_SHA', 'RSA_WITH_RC4_128_SHA', 'RSA_WITH_RC4_128_MD5']
                |        compression_methods_length= 0x1
                |        compression_methods= ['NULL']
                |        extensions_length= 0x7f
                |        \extensions\
                |         |###[ TLS Extension ]###
                |         |  type= server_name
                |         |  length= 0x17
                |         |###[ TLS Extension Servername Indication ]###
                |         |     length= 0x15
                |         |     \server_names\
                |         |      |###[ TLS Servername ]###
                |         |      |  type= host
                |         |      |  length= 0x12
                |         |      |  data= 'ad.doubleclick.net'
                |         |###[ TLS Extension ]###
                |         |  type= renegotiation_info
                |         |  length= 0x1
                |         |###[ TLS Extension Renegotiation Info ]###
                |         |     length= 0x0
                |         |     data= ''
                |         |###[ TLS Extension ]###
                |         |  type= supported_groups
                |         |  length= 0x8
                |         |###[ TLS Extension Elliptic Curves ]###
                |         |     length= 0x6
                |         |     elliptic_curves= ['secp256r1', 'secp384r1', 'secp521r1']
                |         |###[ TLS Extension ]###
                |         |  type= ec_point_formats
                |         |  length= 0x2
                |         |###[ TLS Extension EC Points Format ]###
                |         |     length= 0x1
                |         |     ec_point_formats= ['uncompressed']
                |         |###[ TLS Extension ]###
                |         |  type= SessionTicket TLS
                |         |  length= 0x0
                |         |###[ TLS Extension ]###
                |         |  type= next_protocol_negotiation
                |         |  length= 0x0
                |         |###[ TLS Extension ]###
                |         |  type= application_layer_protocol_negotiation
                |         |  length= 0x1a
                |         |###[ TLS Extension Application-Layer Protocol Negotiation ]###
                |         |     length= 0x18
                |         |     \protocol_name_list\
                |         |      |###[ TLS ALPN Protocol ]###
                |         |      |  length= 0x8
                |         |      |  data= 'spdy/3.1'
                |         |      |###[ TLS ALPN Protocol ]###
                |         |      |  length= 0x5
                |         |      |  data= 'h2-14'
                |         |      |###[ TLS ALPN Protocol ]###
                |         |      |  length= 0x8
                |         |      |  data= 'http/1.1'
                |         |###[ TLS Extension ]###
                |         |  type= 0x7550
                |         |  length= 0x0
                |         |###[ TLS Extension ]###
                |         |  type= status_request
                |         |  length= 0x5
                |         |###[ Raw ]###
                |         |     load= '\x01\x00\x00\x00\x00'
                |         |###[ TLS Extension ]###
                |         |  type= signed_certificate_timestamp
                |         |  length= 0x0
                |         |###[ TLS Extension ]###
                |         |  type= signature_algorithms
                |         |  length= 0x12
                |         |###[ TLS Extension Signature And Hash Algorithm ]###
                |         |     length= 0x10
                |         |     \algs\
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha256
                |         |      |  sig_alg= rsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha384
                |         |      |  sig_alg= rsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha1
                |         |      |  sig_alg= rsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha256
                |         |      |  sig_alg= ecdsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha384
                |         |      |  sig_alg= ecdsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha1
                |         |      |  sig_alg= ecdsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha256
                |         |      |  sig_alg= dsa
                |         |      |###[ TLS Signature Hash Algorithm Pair ]###
                |         |      |  hash_alg= sha1
                |         |      |  sig_alg= dsa

Full Handshake with Application Data (DHE\_RSA\_WITH\_AES\_128\_CBC\_SHA)
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

see /examples/full\_rsa\_connection\_with\_application\_data.py

::

    # python examples/full_rsa_connection_with_application_data.py localhost 443
    Connected to server: ('localhost', 443)
    ###[ SSL/TLS ]###
      \records   \
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_1
       |  length    = 0x2a
       |###[ TLS Handshake ]###
       |     type      = server_hello
       |     length    = 0x26
       |###[ TLS Server Hello ]###
       |        version   = TLS_1_1
       |        gmt_unix_time= 1439578475
       |        random_bytes= 'S-\x0f\x1bt\x95\xcc\xa9wwI\xb9\xf5\x10\x12\x11*\x82%\xdd\xb6\x1e\xc0b\xdc\xac\x9b'
       |        session_id_length= 0x0
       |        session_id= ''
       |        cipher_suite= DHE_RSA_WITH_AES_128_CBC_SHA
       |        compression_method= NULL
       |        \extensions\
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_1
       |  length    = 0x2de
       |###[ TLS Handshake ]###
       |     type      = certificate
       |     length    = 0x2da
       |###[ TLS Certificate List ]###
       |        length    = 0x2d7
       |        \certificates\
       |         |###[ TLS Certificate ]###
       |         |  length    = 0x2d4
       |         |  \data      \
       |         |   |###[ X509Cert ]###
       |         |   |  version   = <ASN1_INTEGER[2L]>
       |         |   |  sn        = <ASN1_INTEGER[14155341744006398450L]>
       |         |   |  sign_algo = <ASN1_OID['.1.2.840.113549.1.1.5']>
       |         |   |  sa_value  = <ASN1_NULL[0L]>
       |         |   |  \issuer    \
       |         |   |   |###[ X509RDN ]###
       |         |   |   |  oid       = <ASN1_OID['.2.5.4.3']>
       |         |   |   |  value     = <ASN1_PRINTABLE_STRING['localhost.localdomain']>
       |         |   |  not_before= <ASN1_UTC_TIME['130425105002Z']>
       |         |   |  not_after = <ASN1_UTC_TIME['230423105002Z']>
       |         |   |  \subject   \
       |         |   |   |###[ X509RDN ]###
       |         |   |   |  oid       = <ASN1_OID['.2.5.4.3']>
       |         |   |   |  value     = <ASN1_PRINTABLE_STRING['localhost.localdomain']>
       |         |   |  pubkey_algo= <ASN1_OID['.1.2.840.113549.1.1.1']>
       |         |   |  pk_value  = <ASN1_NULL[0L]>
       |         |   |  pubkey    = <ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]>
       |         |   |  \x509v3ext \
       |         |   |   |###[ X509v3Ext ]###
       |         |   |   |  val       = <ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]>
       |         |   |  sign_algo2= <ASN1_OID['.1.2.840.113549.1.1.5']>
       |         |   |  sa2_value = <ASN1_NULL[0L]>
       |         |   |  signature = <ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']>
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_1
       |  length    = 0x20d
       |###[ TLS Handshake ]###
       |     type      = server_key_exchange
       |     length    = 0x209
       |###[ TLS Server Key Exchange ]###
       |###[ TLS Diffie-Hellman Server Params ]###
       |           p_length  = 0x80
       |           p         = '\xd6}\xe4@\xcb\xbb\xdc\x196\xd6\x93\xd3J\xfd\n\xd5\x0c\x84\xd29\xa4_R\x0b\xb8\x81t\xcb\x98\xbc\xe9Q\x84\x9f\x91.c\x9cr\xfb\x13\xb4\xb4\xd7\x17~\x16\xd5Z\xc1y\xbaB\x0b*)\xfe2JFzc^\x81\xffY\x017{\xed\xdc\xfd3\x16\x8aF\x1a\xad;r\xda\xe8\x86\x00x\x04[\x07\xa7\xdb\xcaxt\x08}\x15\x10\xea\x9f\xcc\x9d\xdd3\x05\x07\xddb\xdb\x88\xae\xaat}\xe0\xf4\xd6\xe2\xbdh\xb0\xe79>\x0f$!\x8e\xb3'
       |           g_length  = 0x1
       |           g         = '\x02'
       |           ys_length = 0x80
       |           y_s       = "\xc9\x1aK\xe5\xc2\xd9@\x83\x05\xd7\xd1J1[\xdb3\xc2\xa8\xb7\xa0\xdd\xc6cFjje\x92d\xc0\n\x1b\xb6N\xf3f\x9c\xa6\xb86\xf3\xd8\x91\xcf\x18\x87|3\x13fh\x8a$\xdf\xd6\xb6D\x9d\x90\xf6\x08*\xee?\x1f\xc3/|\xbe\xbc\xdd\xf0\x9aX\x8b\x00E\x06\x01\x9a\xc3\xfc\xb2\x1b\xa5\xa7>3\xc8\x95\x07\xfb\x84\x1b\xf9\xa2!%\xfc\xf4\xca`\x1a'\xd1\xeaj\x15c%\xe7\xa8 \xfe,E\x82\x8e\xc2S\xd4e\x88\xf6\xde\xa7\xd5 "
       |           sig_length= 0x100
       |           sig       = '1\xd5!6H\xfa\x0e\xe1\x7f\xa8\x13!\x83\x05X1\x92\xab\x9e^\x8c\xa1\xe2\x05Q\xdajb\x1b\x98\xc0\xc0y\xcbJ5!@P\xe1\xf02\xc9Ar@\xf5\x1d\xe3\xa7<\x10:\xcd\xab\xa6\r\xf2p\xbc@&l8\xf9|\xcd\xc6\xf5K\x1c\xbd\xb0P1\x18W\x9b98O\xa6\xf4\x95\nm\x92\xb4\xf8"o\xeb\xcc\xf7\xbd\xa6\xf5\x9b\xc9\xe1Iw\xe8\xefkn\x13,\x7f\\\x7f(\xc7X\xad|\x19\xbd\n\x85\xcd1\xa3\xb6=\xd1\xda\xd1\xec\x95J\x82\xf4\xcc/wz P\x16\xc3\x99y\xc1\x08A\xec\x11\xeb\xb6tA*+\xff\xd5\x0e\xdb\xf0I\xb5^\x8d2\xc0\x8b\x06yuw\xe9Z\x80v\xd8\xca\xe4\x1f&\x14\xd4\x8e\x13\xe4\xef/6Jq\xe6\x87Y\xb6i\x03Y\xa88\xf3\xe6|b8n\xae\xf4\x81\xc2\xd6\xcd\x82\xe9=\xe1\xfe\r\x90\x9fp\xa4\t\xe8\xd4\x7fL\xa35\xaa#\xaa\x9a\x05\xbfO\xe9w\x11d\xa4\xa7\x98?\xcb\xec\x1c\xc6:l\x0cb7\xb0!,P\xcc'
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_1
       |  length    = 0x4
       |###[ TLS Handshake ]###
       |     type      = server_hello_done
       |     length    = 0x0
    ###[ SSL/TLS ]###
      \records   \
       |###[ TLS Record ]###
       |  content_type= change_cipher_spec
       |  version   = TLS_1_1
       |  length    = 0x1
       |###[ TLS ChangeCipherSpec ]###
       |     message   = '\x01'
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_1
       |  length    = 0x40
       |###[ TLS Plaintext ]###
       |     data      = '\x14\x00\x00\x0c\x94\tJ\xb0\xe5\x8a\xcb\xceN\xa3\x16\x86'
       |     explicit_iv= '\xbd\xd3\xcf\x0e\xd6Q\xba\xec:\xad\xc0\xb8\x81%a!'
       |     mac       = "@*'?:\x1bCR\xf5UZ\xcb\t\xbc\x12CwW\xfc\x01"
       |     padding   = '\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
       |     padding_len= 0xb
    Finished handshake. Sending application data (GET request)
    Got response from server
    ###[ SSL/TLS ]###
      \records   \
       |###[ TLS Record ]###
       |  content_type= application_data
       |  version   = TLS_1_1
       |  length    = 0x140
       |###[ TLS Plaintext ]###
       |     data      = 'HTTP/1.1 200 OK\r\nDate: Fri, 14 Aug 2015 18:54:36 GMT\r\nServer: Apache/2.2.22 (Debian)\r\nLast-Modified: Thu, 25 Apr 2013 10:50:57 GMT\r\nETag: "46fc5-b1-4db2d317b0640"\r\nAccept-Ranges: bytes\r\nContent-Length: 177\r\nVary: Accept-Encoding\r\nContent-Type: text/html\r\nX-Pad: avoid browser bug\r\n\r\n'
       |     explicit_iv= '\xa7\xb5p\xf9\x87!\x89\x1fS{\xb3\x90\x86=]w'
       |     mac       = '\xaf\xcf\x85.\x1f\xed\x18\x97\xf1L.\xa1\x03\xabh\xcd\xc6\xaa\xcb\xdf'
       |     padding   = ''
       |###[ TLS Record ]###
       |  content_type= application_data
       |  version   = TLS_1_1
       |  length    = 0xe0
       |###[ TLS Plaintext ]###
       |     data      = '<html><body><h1>It works!</h1>\n<p>This is the default web page for this server.</p>\n<p>The web server software is running but no content has been added, yet.</p>\n</body></html>\n'
       |     explicit_iv= 'FqV\x86\xe8v\xafoJz\x1c\xdb\xc6\x0b\x8ab'
       |     mac       = '\x15\x9b!\x183\xea\xb0\xa0\x15\xeedc2H\xd8\x97\xf8\x8d\xaay'
       |     padding   = '\n\n\n\n\n\n\n\n\n\n'
       |     padding_len= 0xa
    <TLSSessionCtx: id=153622476
             params.handshake.client=<TLSClientHello  version=TLS_1_1 cipher_suites=['DHE_RSA_WITH_AES_128_CBC_SHA'] compression_methods=['NULL'] |>
             params.handshake.server=<TLSServerHello  version=TLS_1_1 gmt_unix_time=1439578475 random_bytes='S-\x0f\x1bt\x95\xcc\xa9wwI\xb9\xf5\x10\x12\x11*\x82%\xdd\xb6\x1e\xc0b\xdc\xac\x9b' session_id_length=0x0 session_id='' cipher_suite=DHE_RSA_WITH_AES_128_CBC_SHA compression_method=NULL |>
             params.negotiated.version=TLS_1_1
             params.negotiated.ciphersuite=DHE_RSA_WITH_AES_128_CBC_SHA
             params.negotiated.key_exchange=DHE
             params.negotiated.encryption=('AES', 16, 'CBC')
             params.negotiated.mac=SHA
             params.negotiated.compression=NULL
             crypto.client.enc=<Crypto.Cipher.AES.AESCipher instance at 0x92d4f2c>
             crypto.client.dec=<Crypto.Cipher.AES.AESCipher instance at 0x92d4f8c>
             crypto.server.enc=<Crypto.Cipher.AES.AESCipher instance at 0x92d4fac>
             crypto.server.dec=<Crypto.Cipher.AES.AESCipher instance at 0x92d4fcc>
             crypto.server.rsa.privkey=None
             crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x92b5bcc>
             crypto.server.dsa.privkey=None
             crypto.server.dsa.pubkey=None
             crypto.client.dh.x='\xac\x93\x94\xd8\xf8\x85hb\xc4\xb5\x17\x80\x1b\xb1\xb9\xcb\xa3v$[\xb5\x95*\xeb\xfb\xc5\xdc\x0c\xa2J\xbe\x08'
             crypto.client.dh.y_c=':\xe97\x06{:\xb2\x13\xb8\xaa\xa8\x1b\xf9\xa5\x13B\xf6\xe0\xe2AY\x97\x9c\xc7\xcf|\xc1XQ\x98\x9e\xc2\xd3\t\xf9\xa7\x9a\xae\x95\xc1i\xc4\xe3\x84D\xdf\x11^Z\x1d7r:\xd9\xa1\xf1\x96\xcf\xdc\x92\x15\x9f-\x9a\xbe\x84 \x9c\x9clQ\x8f\xe7p\x9c\x8f\xcf\xefT)!\x10I\xb9\x99\xc5\x99\xe1\x1f\x03\r\xf8\xa5\xb1o\t\x01t\x1a\x0e\x1c\x029\xc49\xf5\x08 _\x03p\xbe\x97uZ\xd2\x0e\x19\xb8l[\xd2\x85\x02\x8e\xc1j\xaa'
             crypto.server.dh.p='\xd6}\xe4@\xcb\xbb\xdc\x196\xd6\x93\xd3J\xfd\n\xd5\x0c\x84\xd29\xa4_R\x0b\xb8\x81t\xcb\x98\xbc\xe9Q\x84\x9f\x91.c\x9cr\xfb\x13\xb4\xb4\xd7\x17~\x16\xd5Z\xc1y\xbaB\x0b*)\xfe2JFzc^\x81\xffY\x017{\xed\xdc\xfd3\x16\x8aF\x1a\xad;r\xda\xe8\x86\x00x\x04[\x07\xa7\xdb\xcaxt\x08}\x15\x10\xea\x9f\xcc\x9d\xdd3\x05\x07\xddb\xdb\x88\xae\xaat}\xe0\xf4\xd6\xe2\xbdh\xb0\xe79>\x0f$!\x8e\xb3'
             crypto.server.dh.g='\x02'
             crypto.server.dh.x=None
             crypto.server.dh.y_s="\xc9\x1aK\xe5\xc2\xd9@\x83\x05\xd7\xd1J1[\xdb3\xc2\xa8\xb7\xa0\xdd\xc6cFjje\x92d\xc0\n\x1b\xb6N\xf3f\x9c\xa6\xb86\xf3\xd8\x91\xcf\x18\x87|3\x13fh\x8a$\xdf\xd6\xb6D\x9d\x90\xf6\x08*\xee?\x1f\xc3/|\xbe\xbc\xdd\xf0\x9aX\x8b\x00E\x06\x01\x9a\xc3\xfc\xb2\x1b\xa5\xa7>3\xc8\x95\x07\xfb\x84\x1b\xf9\xa2!%\xfc\xf4\xca`\x1a'\xd1\xeaj\x15c%\xe7\xa8 \xfe,E\x82\x8e\xc2S\xd4e\x88\xf6\xde\xa7\xd5 "
             crypto.session.encrypted_premaster_secret=None
             crypto.session.premaster_secret='\xb7`\xc2\xb2\x99\xeb\xbd\xbee\x9cD\xaf\x15A\x1a3\x1b\x1b\xc6\xf3UKf\xda\xd1\xe8\x02\xf2\xce\x10\xe5$\xe3J/\x1cK\x1b\x9fP5b\xc5\xa0\xab\x1c_\xca\x0cH\xb3\xfb\x10q\x83,\x148\xb5\xf1\x0e\x8d\xd1\xfd\x03\xa2,\xa3\xd1,\xc3i)\x0c\xe9p\xd0\xc7:2\xe5\xdb1\xb3\x9f;h4\xc5\xce\xad\xa2\x1d\xf4\xc7-\xb5)\x99l\x93\xc5~\x92\x1f\xe0b\xc5\xea\xb6(\xee\x9eHT\x01\xcb\x9a\xa5\x07p\x02\x13\xf3W\xf4\xf4V'
             crypto.session.master_secret='\x00y\x00b\xfb\xb7\x95\x1c\x8d\xaa\x0f2q\xc9G<\xf8\x15B`pp\x05\x88\xb6\x02\x00\t:k\xc1\xd4t\xdc&\xa6\x040\xfa4z8\x18yVz\xcd\x00'
             crypto.session.randombytes.client='U\xce9k\xb0l\x89\xfe\x95\xe45\xef\x88g\xe8\x1cz%wc\xb7\xd1\xcc\xd5,\x03Xx\x0eB\xd9@'
             crypto.session.randombytes.server='U\xce9kS-\x0f\x1bt\x95\xcc\xa9wwI\xb9\xf5\x10\x12\x11*\x82%\xdd\xb6\x1e\xc0b\xdc\xac\x9b\x00'
             crypto.session.key.client.mac='\xd9\xdcX\xf9\x83\x10j\xf9\x9bz8i\nzt\xc2|wn\x11'
             crypto.session.key.client.encryption='S\xa8F\x18x\xae\xd5\x0e\x97\xdb\x05PU-+"'
             crypto.session.key.cllient.iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
             crypto.session.key.server.mac='\xda\xe2\x9fw\xe0\x87\xabDD\xfb\xfc\xa1&\xff\xf1\x82\x8e\xe5\xd38'
             crypto.session.key.server.encryption='\x981\xbf\xcb\x1b<\xa3!\xa2\x85[I\xafb\xe2\xfe'
             crypto.session.key.server.iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
             crypto.session.key.length.mac=20
             crypto.session.key.length.encryption=16
             crypto.session.key.length.iv=16
    >

Full Handshake with Application Data (ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA256)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

see /examples/full\_rsa\_connection\_with\_application\_data.py

::

    # python examples/full_rsa_connection_with_application_data.py localhost 443
    Connected to server: ('localhost', 443)
    ###[ SSL/TLS ]###
      \records   \
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_2
       |  length    = 0x2a
       |###[ TLS Handshake ]###
       |     type      = server_hello
       |     length    = 0x26
       |###[ TLS Server Hello ]###
       |        version   = TLS_1_2
       |        gmt_unix_time= 1450127754
       |        random_bytes= 'b\x81\x06Q\xca\x9a71N\xc5<TT\xfb!R\x01\x87H\xe7\t\x11\xec\x9f\xd9D\xfa\xa3'
       |        session_id_length= 0x0
       |        session_id= ''
       |        cipher_suite= ECDHE_RSA_WITH_AES_128_CBC_SHA256
       |        compression_method= NULL
       |        \extensions\
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_2
       |  length    = 0x2de
       |###[ TLS Handshake ]###
       |     type      = certificate
       |     length    = 0x2da
       |###[ TLS Certificate List ]###
       |        length    = 0x2d7
       |        \certificates\
       |         |###[ TLS Certificate ]###
       |         |  length    = 0x2d4
       |         |  \data      \
       |         |   |###[ X509Cert ]###
       |         |   |  version   = <ASN1_INTEGER[2L]>
       |         |   |  sn        = <ASN1_INTEGER[14155341744006398450L]>
       |         |   |  sign_algo = <ASN1_OID['.1.2.840.113549.1.1.5']>
       |         |   |  sa_value  = <ASN1_NULL[0L]>
       |         |   |  \issuer    \
       |         |   |   |###[ X509RDN ]###
       |         |   |   |  oid       = <ASN1_OID['.2.5.4.3']>
       |         |   |   |  value     = <ASN1_PRINTABLE_STRING['localhost.localdomain']>
       |         |   |  not_before= <ASN1_UTC_TIME['130425105002Z']>
       |         |   |  not_after = <ASN1_UTC_TIME['230423105002Z']>
       |         |   |  \subject   \
       |         |   |   |###[ X509RDN ]###
       |         |   |   |  oid       = <ASN1_OID['.2.5.4.3']>
       |         |   |   |  value     = <ASN1_PRINTABLE_STRING['localhost.localdomain']>
       |         |   |  pubkey_algo= <ASN1_OID['.1.2.840.113549.1.1.1']>
       |         |   |  pk_value  = <ASN1_NULL[0L]>
       |         |   |  pubkey    = <ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]>
       |         |   |  \x509v3ext \
       |         |   |   |###[ X509v3Ext ]###
       |         |   |   |  val       = <ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]>
       |         |   |  sign_algo2= <ASN1_OID['.1.2.840.113549.1.1.5']>
       |         |   |  sa2_value = <ASN1_NULL[0L]>
       |         |   |  signature = <ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']>
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_2
       |  length    = 0x14d
       |###[ TLS Handshake ]###
       |     type      = server_key_exchange
       |     length    = 0x149
       |###[ TLS Server Key Exchange ]###
       |###[ TLS EC Diffie-Hellman Server Params ]###
       |           curve_type= named_curve
       |           curve_name= secp256r1
       |           p_length  = 0x41
       |           p         = "\x04\x1b\x85z\xe3\xf1\xfe\x107\xfa\x1d\x85b2\xe2\x96\x85'\x80\n\x9c\x85\xa5\xfa\x10&L\xb9\x82\x18\xe3\xd5\xff\x0eD|(g\x1c\x03\x9b\xe2\xa8\x1f\x92\x8b\xa7\xb8\xeb\xd8\xf6\x14v\xafQ\x94U1[\xc0d1\xff\xc2\xca"
       |           hash_type = sha1
       |           sig_type  = rsa
       |           sig_length= 0x100
       |           sig       = '\xc07E\xab\xe9\xb6\xe5\x8a_\x1f;\x7f>\x8c\xb5\xe0\xf2:\xbb\xeaIk\xee0f\xc0\xef\x94`\xfc\x9e\x00\x0e\x00\x14\x01\x0b\x01\x9akqXw\xc90AO\x1ar\xf4\x82\x86Y`\xb5;\xad]\x9e\x16\x866\x0c:"O\xf3l\x0c\xd8\x14\xda\x17E+\x14\xd5F\x07\xf3\xafF\x0f.+\x05i\xc1\x13\x0f2\x0f\xc0l(\x86\xa0N\x08\xad\xd19&i2\' \x0e\x19}\xb6\xbf\xed\xf1\xbf\x89\xe9\xd7\x179I\xe2$\xa4\xd4pX\xfb\x0c\t-5\x8f\xe69R\xf1U\xf2\xfc\xd3\x0c\x14\xa7f\xf9\xba(t\x0b\xec\x82?wWe\x88\xf8\x943Kf\xa8`\xf5\xa0b\xdea\xc4\xef\x8e\xcc\xbbb\x97\x0b\x00\xb9\x02\xf7\xf6\x1a\xf8\xedjv\xa6 \xfc\x95!\x93\x1c\xfd\x13Y\x1c(\x07\x95\xbf\xa8\x17\xd5\x96\xd5\xa3\xc4c\xcd\xfa\xac\x12U|!ti\x15O\xf5\xd3F\xdd\x7fr\xf5\x83\x11\xb9\xf7`\x0f\xf9?<\x96\xd8dL\xcd\x02\x1f\xf6\x12\x07\x14\xa1\x8d#\xde9\x86J]'
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_2
       |  length    = 0x4
       |###[ TLS Handshake ]###
       |     type      = server_hello_done
       |     length    = 0x0
    ###[ SSL/TLS ]###
      \records   \
       |###[ TLS Record ]###
       |  content_type= change_cipher_spec
       |  version   = TLS_1_2
       |  length    = 0x1
       |###[ TLS ChangeCipherSpec ]###
       |     message   = '\x01'
       |###[ TLS Record ]###
       |  content_type= handshake
       |  version   = TLS_1_2
       |  length    = 0x50
       |###[ TLS Plaintext ]###
       |     data      = '\x14\x00\x00\x0c\x10s\xd9?)WB\xcf\xffY\xed}'
       |     explicit_iv= '\xca7\xa8\x86\x86\xd2\xe1\x18&\xf9r-\x8a\x86\xbf\x16'
       |     mac       = '\xbf\xb8\x07\x15\xc5\x91\xe4SBLQ\xef\x9b\xdc\xcb\x89d\xb5\xde\xec\x11T\x98gG>T\xc4\xe8\x8b\n\x03'
       |     padding   = '\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
       |     padding_len= 0xf
    Finished handshake. Sending application data (GET request)
    Got response from server
    ###[ SSL/TLS ]###
      \records   \
       |###[ TLS Record ]###
       |  content_type= application_data
       |  version   = TLS_1_2
       |  length    = 0x150
       |###[ TLS Plaintext ]###
       |     data      = 'HTTP/1.1 200 OK\r\nDate: Mon, 14 Dec 2015 21:15:56 GMT\r\nServer: Apache/2.2.22 (Debian)\r\nLast-Modified: Thu, 25 Apr 2013 10:50:57 GMT\r\nETag: "46fc5-b1-4db2d317b0640"\r\nAccept-Ranges: bytes\r\nContent-Length: 177\r\nVary: Accept-Encoding\r\nContent-Type: text/html\r\nX-Pad: avoid browser bug\r\n\r\n'
       |     explicit_iv= '\x04\xa4lS\xa1\xbe\xeaI\xca\xc9Zp\xa6\xc8\x94\x9e'
       |     mac       = '5\xb374\xeb\xd7\x990\xaf\x11/\xd8\x8c\x86\x9f\x8cVm\xe1\xfbD>P\xf1\x84\xd4\xb1\x7f[Ku\n'
       |     padding   = '\x04\x04\x04\x04'
       |     padding_len= 0x4
       |###[ TLS Record ]###
       |  content_type= application_data
       |  version   = TLS_1_2
       |  length    = 0xf0
       |###[ TLS Plaintext ]###
       |     data      = '<html><body><h1>It works!</h1>\n<p>This is the default web page for this server.</p>\n<p>The web server software is running but no content has been added, yet.</p>\n</body></html>\n'
       |     explicit_iv= '\x19\t-\xe8\xa5\xe3;\xad^\x8d\x8d\xf2I\x1c\xcb\xad'
       |     mac       = '<\xd5\xb5\x90\x9d\x9b\x8c8B\xc1\xe8\xfb\xdd\x91\n\x8b\xaee\xab]\xfd\xd5kD\xc8\x86\xa1\x02YR\x1e\x9a'
       |     padding   = '\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
       |     padding_len= 0xe
    <TLSSessionCtx: id=151963340
             params.handshake.client=<TLSClientHello  version=TLS_1_2 cipher_suites=['ECDHE_RSA_WITH_AES_128_CBC_SHA256'] compression_methods=['NULL'] |>
             params.handshake.server=<TLSServerHello  version=TLS_1_2 gmt_unix_time=1450127754 random_bytes='b\x81\x06Q\xca\x9a71N\xc5<TT\xfb!R\x01\x87H\xe7\t\x11\xec\x9f\xd9D\xfa\xa3' session_id_length=0x0 session_id='' cipher_suite=ECDHE_RSA_WITH_AES_128_CBC_SHA256 compression_method=NULL |>
             params.negotiated.version=TLS_1_2
             params.negotiated.ciphersuite=ECDHE_RSA_WITH_AES_128_CBC_SHA256
             params.negotiated.key_exchange=ECDHE
             params.negotiated.encryption=('AES', 16, 'CBC')
             params.negotiated.mac=SHA256
             params.negotiated.compression=NULL
             crypto.client.enc=<Crypto.Cipher.AES.AESCipher instance at 0x913598c>
             crypto.client.dec=<Crypto.Cipher.AES.AESCipher instance at 0x91359ec>
             crypto.server.enc=<Crypto.Cipher.AES.AESCipher instance at 0x9135a0c>
             crypto.server.dec=<Crypto.Cipher.AES.AESCipher instance at 0x9135a2c>
             crypto.server.rsa.privkey=None
             crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x912ef8c>
             crypto.server.dsa.privkey=None
             crypto.server.dsa.pubkey=None
             crypto.client.dh.x=None
             crypto.client.dh.y_c=None
             crypto.server.dh.p=None
             crypto.server.dh.g=None
             crypto.server.dh.x=None
             crypto.server.dh.y_s=None
             crypto.client.ecdh.curve_name=None
             crypto.client.ecdh.priv='^\xba\xeb\xcc\xb3>\x85\xa4O\x88#\t\xfe\x11etc\xe3HE\xdf\xab5"\x00*\xa7\xa4\xba\x16\rY'
             crypto.client.ecdh.pub=(15593007407665255161332890480389306948921121224892181265648081329388797451046, 97367016829523129655161775995807426469043502553948069450170722834830665800268) on "secp256r1" => y^2 = x^3 + 115792089210356248762697446949407573530086143415290314195533631308867097853948x + 41058363725152142129326129780047268409114441015993725554835256314039467401291 (mod 115792089210356248762697446949407573530086143415290314195533631308867097853951)
             crypto.server.ecdh.curve_name='secp256r1'
             crypto.server.ecdh.priv=None
             crypto.server.ecdh.pub=(12448285729810697387785923206705205168894064463590796449895082178698960688639, 6453382386374218660658583494811319811574853038993757274506963746262301524682) on "secp256r1" => y^2 = x^3 + 115792089210356248762697446949407573530086143415290314195533631308867097853948x + 41058363725152142129326129780047268409114441015993725554835256314039467401291 (mod 115792089210356248762697446949407573530086143415290314195533631308867097853951)
             crypto.session.encrypted_premaster_secret=None
             crypto.session.premaster_secret='\xd8\xf0&5\x02\xcar^(\xd9\x1b0X\xb5`\x89\x16\xc0HM\x85[*\x93\xacx\xfbj\x86O\x01\x83'
             crypto.session.master_secret='\xb91\xaa&\xfc\xac\xf7\x12\xca\xa0\xa8\xc5\xd5\x9e\xdf\x14\x877\xdf(#\xe0\x9c\xc6\xf1\x93@\x15\x8dgS4\xe0\x915\x1a\x1d\xcc\x10g\xde\x16=\x0f\x1a\x02s\xe7'
             crypto.session.randombytes.client='Vo1\x8aP\x01,C\xc8(\x17\x8eb}\xeeZ\xde\xb6\xd0\xf7\xd7\x96)\xc0\xb2\xc9\xb4\x10\xc1P\\J'
             crypto.session.randombytes.server='Vo1\x8ab\x81\x06Q\xca\x9a71N\xc5<TT\xfb!R\x01\x87H\xe7\t\x11\xec\x9f\xd9D\xfa\xa3'
             crypto.session.key.client.mac='m\xbe\x8b\xc1\x06\xba;%\xd5\xa7.\xc1\xc0|6\x17\x7f\xd8k\xac!4o\xcdWvz7\xc4\xec\x95\xb5'
             crypto.session.key.client.encryption='\xa8\x93Ro\xe0\xc5\x93E\xaa1\xa0p0!\x04p'
             crypto.session.key.cllient.iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
             crypto.session.key.server.mac='k\xc5\xa2VU\xcd\x1f\xf9;dF2\xb5\x15n[\xf8\xff\xd3\xb5\xfc\xf7(\x99\xe8q\\A\xf0\xedeY'
             crypto.session.key.server.encryption='#\xc0%-;\xc1\xfa\xbc\xdbe\x04f\xaa\xf3\xc7\xec'
             crypto.session.key.server.iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
             crypto.session.key.length.mac=32
             crypto.session.key.length.encryption=16
             crypto.session.key.length.iv=16
    >

SCSV Fallback Testing
'''''''''''''''''''''

socket stream example to test remote implementations for protocol
downgrading attemps (following latest SSL POODLE attacks) -
examples/SCSV\_fallback\_test.py

::

    for: ('google.com', 443)
       record      hello
    ('SSL_3_0', 'SSL_3_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
    ('SSL_3_0', 'TLS_1_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
    ('SSL_3_0', 'TLS_1_2')  ... resp: TLSServerHello:            outer TLS_1_2 inner TLS_1_2
    ('SSL_3_0', 'TLS_1_1')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
    ('TLS_1_0', 'SSL_3_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
    ('TLS_1_0', 'TLS_1_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
    ('TLS_1_0', 'TLS_1_2')  ... resp: TLSServerHello:            outer TLS_1_2 inner TLS_1_2
    ('TLS_1_0', 'TLS_1_1')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
    ('TLS_1_2', 'SSL_3_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
    ('TLS_1_2', 'TLS_1_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
    ('TLS_1_2', 'TLS_1_2')  ... resp: TLSServerHello:            outer TLS_1_2 inner TLS_1_2
    ('TLS_1_2', 'TLS_1_1')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
    ('TLS_1_1', 'SSL_3_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
    ('TLS_1_1', 'TLS_1_0')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
    ('TLS_1_1', 'TLS_1_2')  ... resp: TLSServerHello:            outer TLS_1_2 inner TLS_1_2
    ('TLS_1_1', 'TLS_1_1')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
    overall:
        TLS_FALLBACK_SCSV_SUPPORTED   ...  True
        SSLv3_ENABLED                 ...  True

SSLv2 dissection
''''''''''''''''

::

    -----------------------
    ###[ SSL/TLS ]###
      \records   \
       |###[ SSLv2 Record ]###
       |  length    = 0x3e
       |  content_type= client_hello
       |###[ SSLv2 Client Hello ]###
       |     version   = SSL_2_0
       |     cipher_suites_length= 0x15
       |     session_id_length= 0x10
       |     challenge_length= 0x10
       |     cipher_suites= [131200, 393280, 65664, 262272, 458944, 524416, 327808]
       |     session_id= 'aaaaaaaaaaaaaaaa'
       |     challenge = 'aaaaaaaaaaaaaaaa'

TLS Sniffer / PCAP decryption
'''''''''''''''''''''''''''''

TLS1.0 Session Context based decryption of RSA\_WITH\_AES\_128\_CBC\_SHA
for known private key

::

    # python examples/sessionctx_sniffer.py 192.168.220.131 443 tests/files/RSA_WITH_AES_128_CBC_SHA_w_key.pcap tests/files/openssl_1_0_1_f_server.pem
    * pcap ready!
    * load servers privatekey for ciphertext decryption (RSA key only): tests/files/openssl_1_0_1_f_server.pem
    |   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 lengunix_time=120678007 random_bytes="Ua\xc1\\w22\xc4\x01s\x8d>\xc0\xd2\xa6\xe2\xb7#4*]#\xaf\x003\xa3'\xa0" session_id_length=0x0ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'ECDHE_RSA_'DHE_RSA_WITH_AES_256_GCM_SHA384', 'DHE_RSA_WITH_AES_256_CBC_SHA256', 'DHE_DSS_WITH_AES_256_CBC_SHA256', 'DHE_RSA_WITH_AES_25_CAMELLIA_256_CBC_SHA', 'ECDH_RSA_WITH_AES_256_GCM_SHA384', 'ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDH_RSA_WITH_AES_256_CBC_TH_AES_256_CBC_SHA', 'RSA_WITH_AES_256_GCM_SHA384', 'RSA_WITH_AES_256_CBC_SHA256', 'RSA_WITH_AES_256_CBC_SHA', 'RSA_WITH_CAME 'ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'ECDHE_RSA_WITH_AES_128_CBC_SHA', 'ECDHE_ECDSA_WHE_RSA_WITH_AES_128_CBC_SHA256', 'DHE_DSS_WITH_AES_128_CBC_SHA256', 'DHE_RSA_WITH_AES_128_CBC_SHA', 'DHE_DSS_WITH_AES_128_CBCC_SHA', 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'ECDH_RSA_WITH_AES_128_GCM_SHA256', 'ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDH__SHA', 'ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'RSA_WITH_AES_128_GCM_SHA256', 'RSA_WITH_AES_128_CBC_SHA256', 'RSA_WITH_AES_128_CBCSHA', 'ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'DHE_DSS_WITH_3DES_EDE_CBC_SHA', 'ECDH_RSA_WITH_3GOTIATION_INFO_SCSV'] compression_methods_length=0x1 compression_methods=['NULL'] extensions_length=0x15d extensions=[<TLSExt'uncompressed', 'ansiX962_compressed_prime', 'ansiX962_compressed_char2'] |>>, <TLSExtension  type=supported_groups length=0x 'sect409k1', 'sect409r1', 'secp384r1', 'sect283k1', 'sect283r1', 'secp256k1', 'secp256r1', 'sect239k1', 'sect233k1', 'sect23', 'sect163r1', 'sect163r2', 'secp160k1', 'secp160r1', 'secp160r2'] |>>, <TLSExtension  type=signature_algorithms length=0x20lgorithm=sha512 sig_alg=rsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha512 sig_alg=dsa |>, <TLAlgorithm  hash_alg=sha384 sig_alg=rsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha384 signature_algo<TLSSignatureHashAlgorithm  hash_alg=sha256 sig_alg=rsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha2orithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha224 sig_alg=rsa |>, <TLSSignatureHashAlgorithm  ha224 sig_alg=ecdsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha1 sig_alg=rsa |>, <TLSSignatureHaalgorithm=sha1 sig_alg=ecdsa |>] |>>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode=peer_allowx00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>] |>>>] |>
    |   192.168.220.131 :443   => 192.168.220.1   :54908 | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 lengix_time=1435009774 random_bytes='\x1d\xc0u!\xbd\xf9\xc3\xd9\xadmYR\xb4G\x93\xeacX\x88\xe1q/\x08\x16xp+$' session_id_length=0xcipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NULL extensions_length=0xa extensions=[<TLSExtension  type=renegotialength=0x1 |<TLSExtHeartbeat  mode=peer_allowed_to_send |>>] |>>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=cates=[<TLSCertificate  length=0x3eb data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[13397879971383713459L]> sign_OID['.2.5.4.6']> value=<ASN1_PRINTABLE_STRING['UK']> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.10']> value=<ASN1_BADTAG[<ASN1_DECORING[12]>}}>]> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.11']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\x19FOR TESTING PURPOSEDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\x1cOpenSSL Test Intermediate CA']{{Codec <ASN1Co1208140148Z']> not_after=<ASN1_UTC_TIME['211016140148Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.6']> value=<ASN1_PRINTABLEOR['\x0c\rOpenSSL Group']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>, <X509RDN  oid=<ASN1_{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<Ad for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=\xf3I("\xd3\xb9\xfe\xe0\xde\xe48\xce\xee"\x1c\xe9\x91;\x94\xd0r/\x87\x85YKf\xb1\xc5\xf5z\x85]\xc2\x0f\xd3.)X6\xccHk\xa2\xa2\xxfd\xea\xf985+\xf4\xe6\x9a\x0e\xf6\xbb\x12\xab\x87!\xc3/\xbc\xf4\x06\xb8\x8f\x8e\x10\x07\'\x95\xe5B\xcb\xd1\xd5\x10\x8c\x92\xbMW\x06U!"%\xdb\xf3\xaa\xa9`\xbfM\xaay\xd1\xab\x92H\xba\x19\x8e\x12\xech\xd9\xc6\xba\xdf\xecZ\x1c\xd8C\xfe\xe7R\xc9\xcf\x02\xxa2\x13J%\xaf\xe6\x1c\xb1%\xbf\xb4\x99\xa2S\xd3\xa2\x02\xbf\x11\x02\x03\x01\x00\x01']> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUEval=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.15']>, <ASN1_BOOLEAN[-1L]>, <ASN1_STRING['\x03\x02\x05\xe0']>]]> |>, <X509v3Ext  val=<Certificate']>]]> |>, <X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.14']>, <ASN1_STRING["\x04\x14\x82\xbc\xcf\x00\x00\x1['.2.5.29.35']>, <ASN1_STRING['0\x16\x80\x146\xc3l\x88\xe7\x95\xfe\xb0\xbd\xec\xce>=\x86\xab!\x81\x87\xda\xda']>]]> |>] sign_["\x00\xa9\xbdMW@t\xfe\x96\xe9+\xd6x\xfd\xb3c\xcc\xf4\x0bM\x12\xcaZt\x8d\x9b\xf2a\xe6\xfd\x06\x11C\x84\xfc\x17\xa0\xeccc6\xb9x02\x081\x9a\xf1\xd9\x17\xc5\xe9\xa6\xa5\x96Km@\xa9[e(\xcb\xcb\x00\x03\x82c7\xd3\xad\xb1\x96;v\xf5\x17\x16\x02{\xbdSSFr4\xd6\b3\x10\xf7l\xc6\x85K-'\xad\n \\\xfb\x8d\x19p4\xb9u_|\x87\xd5\xc3\xec\x93\x13A\xfcs\x03\xb9\x8d\x1a\xfe\xf7&\x86I\x03\xa9\xc5\\xc1C\xc7\xe0%\xb6\xf1\xd3\x00\xd7@\xabK\x7f+z>\xa6\x99LT"]> |> |>] |>>>, <TLSRecord  content_type=handshake version=TLS_1_0
    <TLSSessionCtx: id=153917580
       params.handshake.client=<TLSClientHello  version=TLS_1_2 gmt_unix_time=120678007 random_bytes="Ua\xc1\\w22\xc4\x01s\x8d>\xength=0x76 cipher_suites=['ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDHE_RSA_WITH_AES_256ECDSA_WITH_AES_256_CBC_SHA', 'DHE_DSS_WITH_AES_256_GCM_SHA384', 'DHE_RSA_WITH_AES_256_GCM_SHA384', 'DHE_RSA_WITH_AES_256_CBC_256_CBC_SHA', 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'ECDH_RSA_WITH_AES_256_GCM_SHA384', '256_CBC_SHA384', 'ECDH_RSA_WITH_AES_256_CBC_SHA', 'ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'RSA_WITH_AES_256_GCM_SHA384', 'RSA_WITHWITH_AES_128_GCM_SHA256', 'ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'ECDHE_ECDSA_WITH_AES_1_WITH_AES_128_GCM_SHA256', 'DHE_RSA_WITH_AES_128_GCM_SHA256', 'DHE_RSA_WITH_AES_128_CBC_SHA256', 'DHE_DSS_WITH_AES_128_CBC_SHSHA', 'DHE_DSS_WITH_SEED_CBC_SHA', 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'ECDH_RSA_WITH_A'ECDH_ECDSA_WITH_AES_128_CBC_SHA256', 'ECDH_RSA_WITH_AES_128_CBC_SHA', 'ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'RSA_WITH_AES_128_G, 'RSA_WITH_CAMELLIA_128_CBC_SHA', 'ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'DHE_RSA_WITH_3DESWITH_3DES_EDE_CBC_SHA', 'RSA_WITH_3DES_EDE_CBC_SHA', 'EMPTY_RENEGOTIATION_INFO_SCSV'] compression_methods_length=0x1 compresslength=0x4 |<TLSExtECPointsFormat  length=0x3 ec_point_formats=['uncompressed', 'ansiX962_compressed_prime', 'ansiX962_compregth=0x32 elliptic_curves=['sect571r1', 'sect571k1', 'secp521r1', 'sect409k1', 'sect409r1', 'secp384r1', 'sect283k1', 'sect283, 'sect193r1', 'sect193r2', 'secp192k1', 'secp192r1', 'sect163k1', 'sect163r1', 'sect163r2', 'secp160k1', 'secp160r1', 'secp1ithm  length=0x1e algs=[<TLSSignatureHashAlgorithm  hash_alg=sha512 sig_alg=rsa |>, <TLSSignatureHashalgorithm=sha512 sig_alg=ecdsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha384 sig_alg=rsa |>, hAlgorithm  hash_alg=sha384 sig_alg=ecdsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha256 signature_a <TLSSignatureHashAlgorithm  hash_alg=sha256 sig_alg=ecdsa |>, <TLSSignatureHashAlgorithm  hash_alg=salgorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha224 sig_alg=ecdsa |>, <TLSSignatureHashAlgorithm a1 sig_alg=dsa |>, <TLSSignatureHashAlgorithm  hash_alg=sha1 sig_alg=ecdsa |>] |>>, <TLSExtensi type=padding length=0xf0 |<Raw  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
       params.handshake.server=<TLSServerHello  version=TLS_1_0 gmt_unix_time=1435009774 random_bytes='\x1d\xc0u!\xbd\xf9\xc3\xd9fa\xa56F\xd8,\x07=\xb1:y\x12P\xc04"\xd4\xfe\x88eC}\xe1\xad]\xdf1' cipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NUtRenegotiationInfo  length=0x0 |>>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode=peer_allowed_to_send |>>
       params.negotiated.version=TLS_1_0
       params.negotiated.ciphersuite=RSA_WITH_AES_128_CBC_SHA
       params.negotiated.key_exchange=RSA
       params.negotiated.encryption=('AES', 16, 'CBC')
       params.negotiated.mac=SHA
       params.negotiated.compression=NULL
       crypto.client.enc=<Crypto.Cipher.AES.AESCipher instance at 0x938042c>
       crypto.client.dec=<Crypto.Cipher.AES.AESCipher instance at 0x932944c>
       crypto.server.enc=<Crypto.Cipher.AES.AESCipher instance at 0x932948c>
       crypto.server.dec=<Crypto.Cipher.AES.AESCipher instance at 0x934bd4c>
       crypto.server.rsa.privkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x932946c>
       crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x93804ec>
       crypto.server.dsa.privkey=None
       crypto.server.dsa.pubkey=None
       crypto.client.dh.x=None
       crypto.client.dh.y_c=None
       crypto.server.dh.p=None
       crypto.server.dh.g=None
       crypto.server.dh.x=None
       crypto.server.dh.y_s=None
       crypto.client.ecdh.curve_name=None
       crypto.client.ecdh.priv=None
       crypto.client.ecdh.pub=None
       crypto.server.ecdh.curve_name=None
       crypto.server.ecdh.priv=None
       crypto.server.ecdh.pub=None
       crypto.session.encrypted_premaster_secret=None
       crypto.session.premaster_secret='\x03\x03Ux\xff,U\x8bM\xf4\xf7\x9b\xe4\xb4\x95\xdf\x90\x02\\I{<\xbe\x87uui\xdc\x16\xffn\xf
       crypto.session.master_secret='\xb7\xe38\x8a\xbc\t9Q\xac,\r\r\x0f(\xbd\\\r<\xa3F\xf2\xc0\xff\xfc\x88\xe1J\xed\x08\xf8\xbc\x
       crypto.session.randombytes.client="\x071fwUa\xc1\\w22\xc4\x01s\x8d>\xc0\xd2\xa6\xe2\xb7#4*]#\xaf\x003\xa3'\xa0"
       crypto.session.randombytes.server='U\x88\x82\xee\x1d\xc0u!\xbd\xf9\xc3\xd9\xadmYR\xb4G\x93\xeacX\x88\xe1q/\x08\x16xp+$'
       crypto.session.key.client.mac=' d\x90\xca\xbdUKe\x96\xc9Y":^w\xa0\x01\xbd=\xbc'
       crypto.session.key.client.encryption="\xc4/\xcb\xc7\n\x85\x0bx\x8c\xd8\x8e+\x83\x8b'{"
       crypto.session.key.cllient.iv='\xdfV\xee\xb1Y\xe1\xae\xfd\xb0\xee\xd9\x1ey\xd2\xf7\xd4'
       crypto.session.key.server.mac='\xcf\xe2F\x97\x81\x9cw\x03\xbc~\x1e\xaf\x15\xdd2J\xd0\x07I\x87'
       crypto.session.key.server.encryption='Zw\xfd\x15\x15a\x0bh@F\xac\xfen\x0ea\xa8'
       crypto.session.key.server.iv='\x16\xcb)\xfa\xfc\x9f\xaar/\x19\xb5\x88\x85o\x8e\xe3'
       crypto.session.key.length.mac=20
       crypto.session.key.length.encryption=16
       crypto.session.key.length.iv=16
    >
    |   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 lengload='\x01\x00\x08\xa9xP\xf3\xdb\xfc\x8b,\xc0C^N\x96ALQ\t\xabW\xcb\x9a\xe4\'\xa96\xb8y\xf8\x1d\xda\x7f\x97Q\x804\x12\n\xe4\xcee\xaeW\xe5\xa4k\xc4^\x95\x8e\xba\r#\xdf\xa2JD\xca\xa0\x98S\x933*<\xc1\n\x18\x1f\xd9\xe4\xad\x82\xb6\xea\x9c\xb8\x14\xa61\xb1x00\x0f1\x0e\xcb\xc3=G^??\xba\xee\xc3\xeb\x16\xe8\xf9\xd6\xdf5e\xb8\r5)\xc7\xc1\xf3\x1d\x85\x181:/\x1d\x16j\xdcS`E\xa7\xc2D"\xc6\xb0Y@\x90\x18\xe4\x1c\xb1\xf3\x9a\xe9\xd9\x80P\xd8\xa9\x01Z\x9d\x000\x95\xbb\xddf\x13\xc9' |>>>>, <TLSRecord  content_typSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSCiphertext  data=',\x8c\xecA\x83\xa7\x8c\xce\xe3\x9e\xb20\xd\x08' |>>] |>
    |-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 lengientRSAParams  length=0x100 data='\x08\xa9xP\xf3\xdb\xfc\x8b,\xc0C^N\x96ALQ\t\xabW\xcb\x9a\xe4\'\xa96\xb8y\xf8\x1d\xda\x7f\x9\x03 \x91\xe2\xa9I\xee\xaeW\xe5\xa4k\xc4^\x95\x8e\xba\r#\xdf\xa2JD\xca\xa0\x98S\x933*<\xc1\n\x18\x1f\xd9\xe4\xad\x82\xb6\xea\\xa0\x8dJ\xf9b\xe4k\x00\x0f1\x0e\xcb\xc3=G^??\xba\xee\xc3\xeb\x16\xe8\xf9\xd6\xdf5e\xb8\r5)\xc7\xc1\xf3\x1d\x85\x181:/\x1d\x10,U\x0c@-[_\x0e\xfd\xc6\xb0Y@\x90\x18\xe4\x1c\xb1\xf3\x9a\xe9\xd9\x80P\xd8\xa9\x01Z\x9d\x000\x95\xbb\xddf\x13\xc9' |>>>>, <TLsage='\x01' |>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSPlaintext  data='\x14\x00\x00\x0c\xc2\xc\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>] |>
    |   192.168.220.131 :443   => 192.168.220.1   :54908 | <SSL  records=[<TLSRecord  content_type=change_cipher_spec version=TLSversion=TLS_1_0 length=0x30 |<TLSCiphertext  data='\x917\xacq\x0f\x8a\xe6\xcd\xc7\x0c\xe8\xe9(\xe2\xda\xbc\xe2\xcd\x8cbP9$\xc
    |-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=change_cipher_spec version=TLSversion=TLS_1_0 length=0x30 |<TLSPlaintext  data='\x14\x00\x00\x0c1\xa9\xd7 v\r\xe1\x0e\xa4M2x' mac='\x9f\x81w\x94\xd1\xd9pe\ng_len=0xb |>>] |>
    |   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1da\xa3?/\xc8\xe0\xbbR\xc0u\xde' |>>, <TLSRecord  content_type=application_data version=TLS_1_0 length=0x70 |<TLSCiphertext  db2\x1e\xdc\x94\xccq\x04\xb7\x8e\xe3[\xcb=\xb1\x0c3\xd8\x82\xec\xa7\x97\xf2\xfe\x1f\xcdp\x94\xc5\x06]\xf0\xee\xadZ\xb4\xe7L<T\\x90\x98\xb3\xf6\x9b\x1e\x8e\xa0\xcd' |>>] |>
    |-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1ng='\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>, <TLSRecord  content_type=application_data version=TLS_68.220.131\r\nAccept: */*\r\n\r\n' mac='\x96\xee\xffa\x13\xd3\xa6\x97C\xa2\xd0y\xf1\x00r(\x07\x12\xb3\xff' padding='\x0c\x0c\
    |   192.168.220.131 :443   => 192.168.220.1   :54908 | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1xea\x9f\x12\x0b\xd5\xf94lR\x7f\xa6g\xf3' |>>, <TLSRecord  content_type=application_data version=TLS_1_0 length=0xb40 |<TLSCipce\x86\xb8\xc5R\xb1\xf0\xcd\x93w\xe1X\n\xaf*(0+t\xe7S\xc7\xe2\x15\x0f\x9f[\xac\x8c\xfbW\x05Zv1|\xdf\xe9\xddT\xf2\x02\x92a\x9f\x92gp\x94\x98\xa6\xe4\xb6\xc6\xce\xefTr\xe8-\xde\xeaI\xf0\xf4bJ\xa3U\xefTg\x05\x83\xfaZ\xc8 Q\x02\xba\xb1\x9e\x95\xb5\xf5\xaxbd\xd0 P\x92\xcc\x18;\xff]e\x00^[\xd6q\xf2w\xd9]\xe7\xde\x1c}\xd4B\xf1x\xf8\x966\x81,\xea\xb8#\x1d\x1b\xc9\xberTQ\x99{]\xeb\cfS\x92e\x0cX|\xb9}\xcd([[d-\xf9\x99\xc2Xe\xe7\x92v\xef \xe5}g;\x13\x93 R\x90s\xf7\x08\xee\xdav\xe6\x17\x84\x8fbZ\xa3\\#\xba\xa2\xe1D\'\x11\xbf\xfe\xeb\xa8\xb9^\x8e\x9bY\x9e\x1a\x95\xb0F\x15\x14\xd0\xf9)\xc9bW\xd2\x16\xbbb\x14+\xe1\x92=cl{P\xfc\x10\xx19\x19\xdfuB$8\xf2\xc1\xa6S\x88\xc3\xc8\xbd\xb4\x87I\xeeA\xf0\nS8mj6\xc8\x0b*\xc0\x9e-\xc2\xcf\xee\xd9#BG\xb2\x1d\xfd*bu\x85x00\x86\xf5\x18\x19H\xf80\x1fG\x01^R(\xc7\xd23z\xcf\xbf\x16\x87\xcaR\xd2\xc6\xdc\xde\xc8R-\x1aAF=\x16\xe2\xd6\xb2!I\xa8L\x98\\xf9@u\xf1"\x8a\xf2\x1f\xe8\xdc\x9cEU\xc5\xa9x\\\xd4\xeb\xd6\'\xb6%\x8a\x18;O\xb9)\xa7\x9c\xe4\xd8q\x1d\xcf\x80\xa0\xb9_C$\xde-D\x1c\x1e\x17\xe7\xc4\xace\xc0\x7fFTk\x8aL\x08\xfe0M>\x87\x0e\x19B\xe2\xad\x12Q!\xb7\'\x9drRZ\x9a\xe5\x01q\x05q\x15\xb4\xad\xd8\x12\xb1@\x88\xbf\x9f\xef3N\x97\xd8V>\x9d#\xee\xed\x9f\xac\xec\x06\xd1\xb9\x99n\xd5\xadT\x15\x9cY\xa9|\xa8\xc1P_x1N\x0c\xxb8zJ\x8b\xf1\x04\xadF\xa1\xa3\x82\x93\xceU\xdbf\x97\xc2$T2\x9c\x1b\xc8\x86\x18A\xf5FyW\xf8\xd0\xba\xb8\x12\xb8\xdeB\xf5\xcfzb\xd3\xfeA\x9b\r\xa4PB\xc4Qy!\xe0T\x14)\xfdb\xb2\x99w\x90\xde@\x0eg\xbb\xa6\r9\x96rd9\xe6\x868\xbe\x84/\t)gxRM=\xe4\x06\xa1\x\x92\xd5\xc0u`\xf15\x95\x05\x92ja\xe3\x80w\x95+\xc4c\xc8Kf/\xaf\xbd\xc4\xc9e\xba\xc4\xb9\xde\x9d\x1b\x96\x9d\x9b \xd6]\xe3Q\x6\xd7~\xe9H\xeb\x90\x88\xa9\n\x85\xcc\xad\x02\x04B\xd9\xca-\xffk&7\x98\xa3\xaf\xddsm\x0fr\x05\xf9=\x12^\xcf\xca\x92\x1cwa\x9fxfe\x9a\xd7T\x90%q\x1c\x17\x95Q\xe0n\xf46\x97\xdf\xa7q\x1b:\x88\x98\xfbxu\x8d*~h\r<\xcf\x7f\xb0\xd8\xd6\xca\x8b}\'G\xdfj\xfd7cb\xc4K\x9b3\xb9\xd9F\xe3\xfa\xc4/\x1fs\xc8\x8c\x11\xde\xd8w\xd9\xee\xd6=|\x12 ?\x9f\xc8\xc2\xa9\xd6\x8b\x0e\xc2\xeaIS\xb1\xexdd\xa5m\xa6\x93\x92\x9a\x1ce\x93S\xadln\xe3\xa2\xc0\x82M\xe3:\xc7\xaa\x9e\xd4\x99{%9\xd5\x1bw\xd4c}\xd7p\xaf\xee\xadx\'H\xcc0?>\xd1\x17\xa2g\xaa\xde\xf6t!{\xd7\xc7\xf5b\xe4\xf45\xa8(\xd0\xdc\xbf\x86\xff\xf9\xc9\xfc\x9b\xc2\xe2@\x0b\x8bm\x06\x98@\xfaa1\xbf_5\xc0s\x9f\xfc\xf3\xb2\xe0\x14\xb04\xa8\xe2\x8eck\xfer\xe2\x81\x8a\x9a\xf2\xbai\xd6\x13G\x8b\xe4}</\xe3\xd9=\xdb\n\xc2\xfd\x14\xf1T5\x02VX\xbea.\x98q\xf9\r\x15,\xe4\xc6g\xf2\x83\xf63Az_ef\x1d\x95,\xc43 \x16E\xca9b\x83JAa\xd5?\x0b\xf0\x7f\xfeY\\x9e,\xd7lH\xc4&Z9Q^\x1e\xbf\x1c\xdbt\x00\xbe\xaf7\xa9\'^MH\xf1\xa3\xd7W[\xbf\x9b\xe0\x00\xce\xa3\x18\x1cz\x1f\xeaV?\xab\x8d-97#\x8e\x08\xd8\xc9\x0cd&9.\xb0\x9d\x13\x03\xe2N<\x0b\xdf\x95\x9e\xa9\xe5R\xac\x1201\xb0"\xe8v]\x89\x0ez~\x1de\x91\xa6\xcd\xfa8\x9d2\xe8|\x02\xe0\xb1\r\xf5\x99N/\x16\xf1ky\xfc\xb5\xf4\xf5\xc3VQ=k\xee\xb8\x8fg\x9c,\x85yu\x05C\xc3\xe5!\x14>\xee,(y\xd8\xf8-\x13\xba\xc2\xf6\x18\xfe\x9c\x10\x15_\x80\xffE~g\x96a\x91\xaf\x1f\x8a1\x12A\x05\xa6T\x01\xa0e\x9e\x0c\x9b\x9b\xc2\xd3\xd7dcg\xd8\nk\xe8n\x1d\x8c\xb1%\xb7\x8bl\xc0]F\xf4X\xe7\x8fE3K\xe3\x06\xa0d\x08\x98\xb4\xb8\x0c\xa7\xc2\xa3O\x93\xcc\xc2PC\x86J\ef\xfd|\xa8\x15__U\x87\r\xae\xf8\x97\x92\xd19\x81s?U\x01\x01\x9f\xe0&\x9f\x99\x87\x7f\x8a\x84\x08n]\xc4\x00\xd6|\x1e-\x83\x90F\x8b\xc0\xcd\xa2+\\\x9b.z\xf1\x1b\xe6G\xe1lscV\x00\x87\x9e\xf1\x93\xb5\xe9\xcb\x164\x140g\xd0\xb9\x1d5\xc7\x7f/\xdc\xb6{|\xcb\xff\x95\xb1\xa8mp\xec\xcb;\x8aM\x11&\xaf\xa3\xe6\r}\xc6K\xd9w\xe3\x99\xc4\rQ\x93A.\x19\xb1:\xec\x1e\xbd{},\x1f\xfe\x10\x984\x7f\xe3\x10\xe9\x85K\x9d\xf0\xa3\x9a\xf3\x85\xf9\xce\xbc*h\x10\xc2\xf9\x8c/\r\x84\xf5\xdf%{iI7&\xf6\x08\x14M]y\xe9\xb0VH\xe3f9\x08\'\xfd]T\xcd\xf8Ey\xc6\xd8"@cq>\xa6\x12d\xbb\xd2\x92uw:#\xe2\xaf\x19\x01\x7f\xe92X\x8f\xad\xe2hO\xf6\x14\xc2c\xee\x8a\x\x83\x0e\x15\xda`}\xa5\xc9\xcbM\xc3\xff\x15\xa0\x9bt\xb9\x8cWwL\x91\xbd\x00\xcdA\nK\\K/\xd2~p{\xf6\xe4\xaav\x07X\n\xef\xfe\x8xc2\x08h\xf3\xc3\xf1\xd5l\xe4\xf5,[\xa0-?\x9b\x12\x99\xaf\xb5\xd30\xc6K\xd3\xf0A\x93e\xf9\xf3\x07\xe0\xe2\x9b\xc3)\x00\xac6\xx1a\x8e\xc5C"\x8a\x0c\xa9\xc6\xe4\xe9\xf4\xc6Sz%L\xe5\xb6f\x86\x9e\x03b\x08\xb0\x86\xc2\x1b\xe4\x9b\x1f\xfb\xa8]fb$\xae\xb3f~ea\xa8\xd4\x99\xea\xb7\xd4J\x9c\xb7\xcd\x10\xa5#\xd8>\xcde\x9a\x9f\x10\xef)\xe1\xfb,\xf3\xee0\xa9\xa4\xe2f\xa5_y\xa7\xb6\x8b)xae0"\xcc\x01m\xe8\xe4 R\x8c\xc6.v\x8c\xdc\x98\xbc\xe5\xf4\xc8\xaa\xc2\xc6\x11i\xa7\xcc\xc9\x10\x9c\xeb\x96\xc4\xd4\xd0\xd0C\b8\xc2\xac\xdb\xad\xda\x86\xde\x0cVc\xea\xfe\xbb-?:\xbb\xf4|\xb1yi\xfb\xafw\xed\xa3]:y(\xa7\xe9etN\xf9cG\x1dux\xad\\\x8c\x84\\x9b\xf4\xa91\xd7\xf2\xc2\x0f\xf1\xd8\x8a~\xee\x17\xa4\x05\x7f\x0ce-O\xd6\xa9\x95\xa3\xe9\xebu\nd\xdc\t\xaa~OU\xd8\x8c\xfa\xb5\x04V"\x96\x8d\x87\x92\xbd\x90\xa4\xbb\x80\x96\x1dG\xb2NDzJBt\xa9\xf8\xcc\xf5\x8c\x1e\x11fP\xba\xbe\xf64"s\xd6$\xc9T\xda)\xd
    |-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1\xe1\xd5' padding='\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>, <TLSRecord  content_type=application_daml\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n<pre>\n\ns_server -accept 443 -cert openssl_1_0_1_f_server.pem -tls1 -cipher AES128v3:AES128-SHA               \n---\nCiphers common between both SSL end points:\nECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES25 ECDHE-ECDSA-AES256-SHA    \nDHE-DSS-AES256-GCM-SHA384  DHE-RSA-AES256-GCM-SHA384  DHE-RSA-AES256-SHA256     \nDHE-DSS-AES256 DHE-DSS-CAMELLIA256-SHA    ECDH-RSA-AES256-GCM-SHA384\nECDH-ECDSA-AES256-GCM-SHA384 ECDH-RSA-AES256-SHA384     ECDH-ECDSA-AE \nAES256-SHA256              AES256-SHA                 CAMELLIA256-SHA           \nECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-      ECDHE-ECDSA-AES128-SHA    \nDHE-DSS-AES128-GCM-SHA256  DHE-RSA-AES128-GCM-SHA256  DHE-RSA-AES128-SHA256     \nDHE-DSS-A      DHE-DSS-SEED-SHA           DHE-RSA-CAMELLIA128-SHA   \nDHE-DSS-CAMELLIA128-SHA    ECDH-RSA-AES128-GCM-SHA256 ECDH-ECDSA      \nECDH-ECDSA-AES128-SHA      AES128-GCM-SHA256          AES128-SHA256             \nAES128-SHA                 SEED-SHA-SHA   EDH-RSA-DES-CBC3-SHA      \nEDH-DSS-DES-CBC3-SHA       ECDH-RSA-DES-CBC3-SHA      ECDH-ECDSA-DES-CBC3-SHA   \nDES-CBC3pher    : AES128-SHA\n    Session-ID: B458EC666AFAA53646D82C073DB13A791250C03422D4FE8865437DE1AD5DDF31\n    Session-ID-ctx: 0E6652DAF255AFACF0E16C286A8D\n    Key-Arg   : None\n    PSK identity: None\n    PSK identity hint: None\n    SRP username: Non\n   1 items in the session cache\n   0 client connects (SSL_connect())\n   0 client renegotiates (SSL_connect())\n   0 cliencept())\n   1 server accepts that finished\n   0 session cache hits\n   0 session cache misses\n   0 session cache timeouts\navailable\n</BODY></HTML>\r\n\r\n' mac='\x97$\x1a\x18\x12B\r6,d\xb0\x9fMq\xdd\xe6\xd2\\\n\xe7' padding='\x08\x08\x08\x08\x08\
    |   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=alert version=TLS_1_0 length=04\xa0\x07N^v\xa83kh\xc0\xfd\xe9' |>>>] |>
    |-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=alert version=TLS_1_0 length=0an\xfbZ\xf5\x82\x16' padding='\t\t\t\t\t\t\t\t\t' padding_len=0x9 |>>] |>

SSL Security Scanner
''''''''''''''''''''

Active Scanner:

::

    # python examples/security_scanner.py active localhost 443 

    An example implementation of a passive TLS security scanner with custom starttls support:

        TLSScanner() generates TLS probe traffic  (optional)
        TLSInfo() passively evaluates the traffic and generates events/warning

        

    Scanning with 10 parallel threads...
    => accepted_ciphersuites
    => accepted_ciphersuites_ssl2
    => compressions
    => heartbleed
    => poodle2
    => scsv
    => secure_renegotiation
    => supported_protocol_versions


    [*] Capabilities (Debug)
    <TLSInfo
            packets.processed: 403
            
            client.versions: set([])
            client.ciphers: set([])
            client.compressions: set([])
            client.preferred_ciphers: set([])
            client.sessions_established: 0
            client.heartbeat: None
            
            server.versions: set([768, 769, 770, 771])
            server.ciphers: set([65, 132, 3, 4, 5, 6, 8, 9, 10, 47, 136, 51, 20, 21, 22, 150, 57, 154, 159, 69, 53])
            server.compressions: set([0])
            server.sessions_established: 0
            server.fallback_scsv: False
            server.heartbeat: 1
            
            server.certificates: set([<TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>, <TLSCertificateList  length=0x2d7 certificates=[<TLSCertificate  length=0x2d4 data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[14155341744006398450L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] not_before=<ASN1_UTC_TIME['130425105002Z']> not_after=<ASN1_UTC_TIME['230423105002Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_PRINTABLE_STRING['localhost.localdomain']> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING["\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01"]> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_STRING['0\x00']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING['\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d']> |> |>] |>])
    >
            
    [*] supported ciphers: 34/326
     * SSLv2_RC4_128_EXPORT40_WITH_MD5 (0x20080)
     * ECDH_anon_WITH_RC4_128_SHA (0xc016)
     * RSA_EXPORT_WITH_RC4_40_MD5 (0x0003)
     * RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)
     * RSA_WITH_RC4_128_SHA (0x0005)
     * RSA_EXPORT_WITH_RC2_CBC_40_MD5 (0x0006)
     * RSA_WITH_IDEA_CBC_SHA (0x0007)
     * RSA_EXPORT_WITH_DES40_CBC_SHA (0x0008)
     * RSA_WITH_DES_CBC_SHA (0x0009)
     * RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
     * ECDH_anon_WITH_3DES_EDE_CBC_SHA (0xc017)
     * ECDHE_RSA_WITH_RC4_128_SHA (0xc011)
     * ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
     * ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
     * DHE_RSA_EXPORT_WITH_DES40_CBC_SHA (0x0014)
     * DHE_RSA_WITH_DES_CBC_SHA (0x0015)
     * DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)
     * ECDH_anon_WITH_AES_256_CBC_SHA (0xc019)
     * ECDH_anon_WITH_AES_128_CBC_SHA (0xc018)
     * RSA_WITH_RC4_128_MD5 (0x0004)
     * DHE_RSA_WITH_SEED_CBC_SHA (0x009a)
     * RSA_WITH_SEED_CBC_SHA (0x0096)
     * DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)
     * SSLv2_RC2_CBC_128_CBC_WITH_MD5 (0x40080)
     * RSA_WITH_AES_128_CBC_SHA (0x002f)
     * DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)
     * DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
     * RSA_WITH_AES_256_CBC_SHA (0x0035)
     * DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
     * SSLv2_DES_64_CBC_WITH_MD5 (0x60040)
     * RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)
     * DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)
     * SSLv2_RC4_128_WITH_MD5 (0x10080)
     * ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)

    [*] supported protocol versions: 5/8
     * SSL_3_0 (0x0300)
     * TLS_1_0 (0x0301)
     * SSL_2_0 (0x0002)
     * TLS_1_1 (0x0302)
     * TLS_1_2 (0x0303)

    [*] supported compressions methods: 1/3
     * NULL (0x0000)

    [*] Events: 16
    * EVENT - HEARTBLEED - vulnerable
    * EVENT - DROWN - SSLv2 with EXPORT ciphers enabled
    * EVENT - CIPHERS - Export ciphers enabled
    * EVENT - CIPHERS - RC4 ciphers enabled
    * EVENT - CIPHERS - MD5 ciphers enabled
    * EVENT - FREAK - server supports RSA_EXPORT cipher suites
    * EVENT - LOGJAM - server supports weak DH-Group (512) (DHE_*_EXPORT) cipher suites
    * EVENT - PROTOCOL VERSION - SSLv2 supported
    * EVENT - PROTOCOL VERSION - SSLv3 supported 
    * EVENT - HEARTBEAT - enabled (non conclusive heartbleed) 
    * EVENT - INSUFFICIENT SERVER CERT PUBKEY SIZE - 2048 >= 640 bits
    * EVENT - SUSPICIOUS SERVER CERT PUBKEY SIZE - 640 not a multiple of 2048 bits
    * EVENT - SERVER CERT PUBKEY FACTORED - trivial private_key recovery possible due to known factors n = p x q. See https://en.wikipedia.org/wiki/RSA_numbers | grep 3107418240490043721350750035888567930037346022842727545720161948823206440518081504556346829671723286782437916272838033415471073108501919548529007337724822783525742386454014691736602477652346609
    * EVENT - DOWNGRADE / POODLE - FALLBACK_SCSV - not honored
    * EVENT - TLS EXTENSION SECURE RENEGOTIATION - not supported
    * EVENT - HEARTBEAT - enabled (non conclusive heartbleed)

    Scan took: 30.60623884201s

Passive Scanner:

::

    # python examples/security_scanner.py sniff 192.168.139.131 443 
    An example implementation of a passive TLS security scanner with custom starttls support:

        TLSScanner() generates TLS probe traffic  (optional)
        TLSInfo() passively evaluates the traffic and generates events/warning

        

    [*] [passive] Scanning in 'sniff' mode...
    Connection: 192.168.139.1:1364 <==> 192.168.139.131:443
    * EVENT - CRIME - client supports compression
    * EVENT - SLOTH - client announces capability of signature/hash algorithm: RSA/sha1
    Connection: 192.168.139.131:443 <==> 192.168.139.1:1364
    * EVENT - CRIME - client supports compression
    * EVENT - SLOTH - client announces capability of signature/hash algorithm: RSA/sha1
    Connection: 192.168.139.131:443 <==> 192.168.139.1:1364
    * EVENT - CRIME - client supports compression
    * EVENT - SLOTH - client announces capability of signature/hash algorithm: RSA/sha1
    * EVENT - CRIME - server supports compression
    * EVENT - INSUFFICIENT SERVER CERT PUBKEY SIZE - 2048 >= 640 bits
    * EVENT - SUSPICIOUS SERVER CERT PUBKEY SIZE - 640 not a multiple of 2048 bits
    * EVENT - SERVER CERT PUBKEY FACTORED - trivial private_key recovery possible due to known factors n = p x q. See https://en.wikipedia.org/wiki/RSA_numbers | grep 3107418240490043721350750035888567930037346022842727545720161948823206440518081504556346829671723286782437916272838033415471073108501919548529007337724822783525742386454014691736602477652346609
    * EVENT - HEARTBEAT - enabled (non conclusive heartbleed) 
    Connection: 192.168.139.1:1364 <==> 192.168.139.131:443

Authors / Contributors
----------------------

-  tintinweb ( http://oststrom.com \| https://github.com/tintinweb)
-  alexmgr ( https://github.com/alexmgr )

