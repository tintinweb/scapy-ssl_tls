[![Build Status](https://buildhive.cloudbees.com/job/tintinweb/job/scapy-ssl_tls/badge/icon)](https://buildhive.cloudbees.com/job/tintinweb/job/scapy-ssl_tls/)

SSL/TLS layers for scapy the interactive packet manipulation tool.

Scapy-SSL/TLS
=============

SSL/TLS and DTLS layers and TLS utiltiy functions for [Scapy](http://www.secdev.org/projects/scapy/).

An offensive stack for SSLv2, SSLv3 (TLS), TLS, DTLS penetration testing providing easy access to packet crafting, automatic dissection, encryption, decryption, session tracking, automated handshakes, TLSSocket abstraction, cryptography containers, predefined hooks, SSL sniffing including minimalistic PCAP stream decryption (RSA_WITH_*), fuzzing and security scanning (Renegotiation, Heartbleed, Poodle, Logjam/Freak, various Buffer overflows, ...).


Features
---------
* SSLv2 handshake
* SSLv3/TLS records
* TLS 1.0, 1.1
* DTLS records
* TLS Session Context / Session Tracking
 * Key sniffing (master_key, ...)
* Sniffing / PCAP processing and decryption


Installation
------------

##### Option 1: pip - download latest release from the python package index

	pip install scapy-ssl_tls
	
##### Option 2: from source
	
	pip install -r requirements.txt
	python setup.py install
	
##### Option 3: manual installation

1) install requirements from requirements.txt

2) copy scapy_ssl_tls/* to *scapy_installation*/scapy/layers 

3) modify *scapy_installation*/scapy/config.py to autoload SSL/TLS 

```diff

	@@ -373,3 +373,3 @@
	load_layers = ["l2", "inet", "dhcp", "dns", "dot11", "gprs", "hsrp", "inet6", "ir", "isakmp", "l2tp",
	-                   "mgcp", "mobileip", "netbios", "netflow", "ntp", "ppp", "radius", "rip", "rtp",
	+                   "mgcp", "mobileip", "netbios", "netflow", "ntp", "ppp", "radius", "rip", "rtp","ssl_tls",
		                "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp" ]
 ```

##### verify installation:
```python
#> scapy
	>>> SSL
	<class 'scapy.layers.ssl_tls.SSL'>
	>>> TLS
	<class 'scapy.layers.ssl_tls.SSL'>
	>>> TLSRecord
	<class 'scapy.layers.ssl_tls.TLSRecord'>
```


## Examples

##### Heartbleed Record

```python
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
```

##### Heartbleed Attack
```python
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
```

##### Dissect TLSClientHello (pcap)

```python
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
            |        cipher_suites= [49195, 49199, 158, 52244, 52243, 49162, 49161, 49171, 49172, 49159, 49169, 51, 50, 57, 156, 47, 53, 10, 5, 4]
            |        compression_methods_length= 0x1
            |        compression_methods= [0]
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
            |         |     elliptic_curves= [23, 24, 25]
            |         |###[ TLS Extension ]###
            |         |  type= ec_point_formats
            |         |  length= 0x2
            |         |###[ TLS Extension EC Points Format ]###
            |         |     length= 0x1
            |         |     ec_point_formats= [0]
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
            |         |     \algorithms\
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha256
            |         |      |  signature_algorithm= rsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha384
            |         |      |  signature_algorithm= rsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha1
            |         |      |  signature_algorithm= rsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha256
            |         |      |  signature_algorithm= ecdsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha384
            |         |      |  signature_algorithm= ecdsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha1
            |         |      |  signature_algorithm= ecdsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha256
            |         |      |  signature_algorithm= dsa
            |         |      |###[ TLS Signature Hash Algorithm Pair ]###
            |         |      |  hash_algorithm= sha1
            |         |      |  signature_algorithm= dsa
```

##### Full Handshake with Application Data (DHE_RSA_WITH_AES_128_CBC_SHA)

see /examples/full_rsa_connection_with_application_data.py

```python
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
   |        gmt_unix_time= 1437000923
   |        random_bytes= '\xef\xe1\xf9\x0f\xa6\x98\xdc\xdd\x03&\x80\x9c\xd5\x9b\x15J.k\x15\xcf\x8f\xbd\xe8\x08wL;('
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
   |         |   |###[ Raw ]###
   |         |   |  load      = '0\x82\x02\xd00\x82\x01\xb8\xa0\x03\x02\x01\x02\x02\t\x00\xc4q\xe0Qe\xc2\x81\xf20\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000 1\x1e0\x1c\x06\x03U\x04\x03\x13\x15localhost.localdomain0\x1e\x17\r130425105002Z\x17\r230423105002Z0 1\x1e0\x1c\x06\x03U\x04\x03\x13\x15localhost.localdomain0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xdcS\xa3%U\r\xe0\xb3\xab5=$\'\x8d\x13\x95cp\x0c\xe2p\xb5\x0e\xe3J\x1fy\x7f\x876\x9cH\xd8Z\x8e\x1c\x04\xc4C\x8e<\x1a\xd1\x90\xbdm\xaa\x08ku<Tw\t\xbd{\xb7wZm\x9cmW\\o\x9dw\xdf\xa3\xe7}\xac!:\x150\xb7\x98lCA\xec\x18\x97\xba#B\x8b\xa1c\xd8aw\xbb\xc6\xc4\x0fbs\x87eT<E\xbf\r\x92\xfc\x8b}7b7\xf12\x19(\x95y+\x12oiW4\xd7\xf5\x06\xf2G\xf2\x15\xfc\xf6\xa6Y\x83\x11\xc7P\\\'\x8b\xd2\x96\xd0\xa2\xb51\xb3\x00N\xb9s\\\x03\x95\xb0\x12\xe1l\x9d\x83\x92uU\x9d\xbd\xdct}@6\r\xbb\xc9\xea@S\xf4D\xbe\x93\x99`xUjF.M\xd8\xbc\xfc\xdb 1\xaa{;\xf3\xec)1\xa9\xe4\xfapl\x18\x07O\x88Y\xc8\xed\xb63\xf2\x7f\xe2~g\xe7\xf9\xc4L\x9d\xcbg\xda\xdf\x1e5\xb3C\x07\xeav\xf0\x13m]\x94\xdaY\xc8\xc3?\x99\xb6\xb6\xb5\xc5bM\x02\x03\x01\x00\x01\xa3\r0\x0b0\t\x06\x03U\x1d\x13\x04\x020\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00X\xaf\xa2B\xb4c\x83}S\x06\x07\xb7\xb6\xa4nT\xeeAS\xe0\x93\x81\x820\x9c\x92\x16\xb3H\xd0\x11Z\x02\\g|\x9f\x0b\x8f\x96\x82\x1a3\x8d\xe1.3\xcd\xe9\xc2K\x990\x8c\x98\x1b\xf6\x03\x1a\x06\xc2l2\xcb+x$-\xd8J9\xae\xc8\xdd\x8a\x7f8\x1e\xf9z\x10\xdd\xf9\x88s\xf5\xd1\xf3i\x7f\x8d\xbahU{]\x9bTu\x81T\xda\x0e`\x86\xd1\xbb\xe4\x98\xb2\r\xa2\x9a9N\xedmOw1I\xe4\xe3GCw\xad\xa2\xe7\x18\x8d"\xb7\x8c~B\xce\xba\xfc+\x8a\x81$\xdb\xc33\x01a\xd8\x9al\xack\x07\xbe\x18f2\x13\xa8\xc2\xf2\xa4\xcb\x86x\xd2\xa9\xf2\xef\xb3\x14<\xb10\x91W\xbfA_F\x81\xe8A\x8ac\xa9\n\x82\n\n\x93\xfd7\xb3Z\xe9\xab\x18\xc0=\x96\x84\x02?UC\xb6\x0ep\xfa\x19\xa6\xfcbM\x9d\x00\xa1\x03`\x0c\xbe\xda;+`\x13\xd6\xbaly\xeb\x02\xf7Mr\x9a\x00\xc1W7~\x89^6I\x1fj5u\xa8 r;\x8d'
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
   |           y_s       = '\xbe?\xcc\x01?\x91)\x8d\x03]\x1a\x92\xcf\xa0\x99\xac\xbd\x84\xabj\x19\x84\x1c\x9f|C!\xaf\xbc+\xfb\xc8\xbf\xf7\xdb\xe6\x91\xc3s\xe91\xe0\xb1J\\\xce\x1e9-\xe7\x08\xf0\xb1k\xc3@\x1b\xd2F\x1bj\xfb\xa3\xa01\xe4y\xc0cA9\xe9\\\xca\xe8\xdc\x01\x9b\x8422\xb0-\xb2\x0b\xd9\x0f\xfb\xfbm\x14!$\x89S\x8a\xe9\xd8\xf1\x93_n\x99-\xe9y\x8d\xaaz<\x9c\xce\x84)\xf8\x16Y86x)x\x1c\x91/h\xcc\x8a'
   |           sig_length= 0x100
   |           sig       = '\xd8\x99\t\xbd\xaa\xe1>\x89G\xaae\xb6%\xe6\x7f\xf5L\x0f\x8f\xe5l\xbc\xfd\x13\x91\x80R\xe3\x9a\x14\xd11\xae\x0c\xd4\t\x83\x9c&e\xb87\xef\xeb\x01\x0c\xcc\xec\x80\xb2\xa6\x87\xc4\xaa\xb6|\x1a\xb5\xd0\xf7P\x9b\xb5\xfd\x0f\xb9\xe4\x01\xbe\xfb\xe9\x1e\xa4\xcf\xd2\xd9\xd3\x9aD\x86\xc59Mu\xb9 \xc2B\x10\xed\xa1\xd8D\xae\xbb\x12\x83u\x959\x16L\xd3z{\xf2\xfaMVGP\x1a\xd2\x98K\xea\xb6\xf4=G\xf9;\x19 \xfd?\x9d\xc6\xf5\xca\xed7?sc\xc5\x89\xc9\xa8\xfd\xd6\x99K\x1ezzb\x7f34\x01\x81\x16\xadds\x01\xb6(\xcb\xe6r\xe2\xdfM=d\xc8o\xcf\xc2\xabjZO*,\x14\xec=u\x91\xb5\xe0\xb0\xa9\xeb\x11\x89Z\x89\x02\xfa\xc1=\xa5$9\x12\xb1\xedt,I\x9c\x16&`\xfc:\xed\x94i\xe9A\xbbY\x92 \xa4\x8au\x19\t\x85\x01\x82\xf0%\xcb\xc9~\xd4\x15CzK\xc5\xbe\xb6\xb73\xdd\x18\x01K\x19\xfe_\xe9q\xc5\x0b\xdbb\x8a'
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
   |     data      = '\x14\x00\x00\x0c\xb6\x87\x0e\xad\xa2\xd4\x8d\x11\x95i(\xbf'
   |     explicit_iv= '\xea\xa4<\xf9\x98\xba*2Rp\xba\x95\x90I\xe5c'
   |     mac       = '\xc9{\xae\xfd\x99c\xe8{\t%\x85\x900I\xf5\x90n\xde\xc8\xdd'
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
   |     data      = 'HTTP/1.1 200 OK\r\nDate: Wed, 15 Jul 2015 22:55:24 GMT\r\nServer: Apache/2.2.22 (Debian)\r\nLast-Modified: Thu, 25 Apr 2013 10:50:57 GMT\r\nETag: "46fc5-b1-4db2d317b0640"\r\nAccept-Ranges: bytes\r\nContent-Length: 177\r\nVary: Accept-Encoding\r\nContent-Type: text/html\r\nX-Pad: avoid browser bug\r\n\r\n'
   |     explicit_iv= '\xfeA\x10\x08n\xfbXw\xdb\xf6\xf2\xbevG%\x8f'
   |     mac       = "s)\xb0\xb3=\x91\x80\xb1\xfa\xba\x99\xd8'\xbf\xf8\xc1\xa65<\xfb"
   |     padding   = ''
   |###[ TLS Record ]###
   |  content_type= application_data
   |  version   = TLS_1_1
   |  length    = 0xe0
   |###[ TLS Plaintext ]###
   |     data      = '<html><body><h1>It works!</h1>\n<p>This is the default web page for this server.</p>\n<p>The web server software is running but no content has been added, yet.</p>\n</body></html>\n'
   |     explicit_iv= '\x86\x1a\xb6\xf6w\x9e\x96\x89\xf4Fr\xa7\xd2xLo'
   |     mac       = '\xec;\x1d\x10\x1d\x9bG#o\xc4\xf0Z\xec\xd8\xa5$U\xd28!'
   |     padding   = '\n\n\n\n\n\n\n\n\n\n'
   |     padding_len= 0xa
<TLSSessionCtx: id=147906796
    params.handshake.client=<TLSClientHello  version=TLS_1_1 cipher_suites=[51] compression_methods=[0] |>
    params.handshake.server=<TLSServerHello  version=TLS_1_1 gmt_unix_time=1437000923 random_bytes='\xef\xe1\xf9\x0f\xa6\x98\xdc\xdd\x03&\x80\x9c\xd5\x9b\x15J.k\x15\xcf\x8f\xbd\xe8\x08wL;(' session_id_length=0x0 session_id='' cipher_suite=DHE_RSA_WITH_AES_128_CBC_SHA compression_method=NULL |>
    params.negotiated.version=TLS_1_1
    params.negotiated.ciphersuite=DHE_RSA_WITH_AES_128_CBC_SHA
    params.negotiated.key_exchange=DHE
    params.negotiated.encryption=('AES', 16, 'CBC')
    params.negotiated.mac=SHA
    params.negotiated.compression=NULL
    crypto.client.enc=<Crypto.Cipher.AES.AESCipher instance at 0x8dc8bcc>
    crypto.client.dec=<Crypto.Cipher.AES.AESCipher instance at 0x8dc8c2c>
    crypto.server.enc=<Crypto.Cipher.AES.AESCipher instance at 0x8dc8c4c>
    crypto.server.dec=<Crypto.Cipher.AES.AESCipher instance at 0x8dc8c6c>
    crypto.server.rsa.privkey=None
    crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x8dbd02c>
    crypto.server.dsa.privkey=None
    crypto.server.dsa.pubkey=None
    crypto.client.dh.x='\x02\xb1P\xbe\xef\xd3\xb1\xe8\x9a\tCfiy\x88j\x0ew\xd2\xe7\xc7D\xb1I\xc1O\x85\xa9\xc3\x16/\x82'
    crypto.client.dh.y_c="^\x07\x03}E\x8e\xe5\x97\xed\xf0`|\xf5\r\xa6\xfdK\x02\xc0\x81\x80\x0f\xcf\x93\xd7\x1d\xdd\xc0]\xe6\xca]lR\xe3\xb8\x13M\xb2,/u=\xb7+:G\xde\x9f\xd0b@\xf8\x96JsZ\x9a6\xa5\x13e\xb3L\xac\x8b\xc1V\r\xae88AP\xe4r\x90tHL\xb6+\xacj\xcf\xbaE0C\xd6,'J\xe1{\xc4\xe0I\x9f\x13LX\xcdu\x14\x92,\x0b2\xe7\x17\xe9\x02+\x0br\x9c!.9\xbd\x0c\x03\x13\x0bG\xb2\xc1"
    crypto.server.dh.p='\xd6}\xe4@\xcb\xbb\xdc\x196\xd6\x93\xd3J\xfd\n\xd5\x0c\x84\xd29\xa4_R\x0b\xb8\x81t\xcb\x98\xbc\xe9Q\x84\x9f\x91.c\x9cr\xfb\x13\xb4\xb4\xd7\x17~\x16\xd5Z\xc1y\xbaB\x0b*)\xfe2JFzc^\x81\xffY\x017{\xed\xdc\xfd3\x16\x8aF\x1a\xad;r\xda\xe8\x86\x00x\x04[\x07\xa7\xdb\xcaxt\x08}\x15\x10\xea\x9f\xcc\x9d\xdd3\x05\x07\xddb\xdb\x88\xae\xaat}\xe0\xf4\xd6\xe2\xbdh\xb0\xe79>\x0f$!\x8e\xb3'
    crypto.server.dh.g='\x02'
    crypto.server.dh.x=None
    crypto.server.dh.y_s='\xbe?\xcc\x01?\x91)\x8d\x03]\x1a\x92\xcf\xa0\x99\xac\xbd\x84\xabj\x19\x84\x1c\x9f|C!\xaf\xbc+\xfb\xc8\xbf\xf7\xdb\xe6\x91\xc3s\xe91\xe0\xb1J\\\xce\x1e9-\xe7\x08\xf0\xb1k\xc3@\x1b\xd2F\x1bj\xfb\xa3\xa01\xe4y\xc0cA9\xe9\\\xca\xe8\xdc\x01\x9b\x8422\xb0-\xb2\x0b\xd9\x0f\xfb\xfbm\x14!$\x89S\x8a\xe9\xd8\xf1\x93_n\x99-\xe9y\x8d\xaaz<\x9c\xce\x84)\xf8\x16Y86x)x\x1c\x91/h\xcc\x8a'
    crypto.session.encrypted_premaster_secret=None
    crypto.session.premaster_secret="+I\xd1\x8f\x13\x99\ny\x00\xfaPa\xda\xc05\xb2\x04\x87\x80\xab\x7f\xb3\xcd\xeb\xe9^\x14\xa8\x1b\xe9<2\x00\xcfuR\x85\xec'\x07;\xf0\xeb\xe4\xb0\xaf\x11\xbb\xc6\xea\xdc^8(%\xda\x9d\xe5\xdcpR\xb4\x0cP\x99\xbf\xf1e^\xb7\x7f\xf20\xc8\x12oP\xbe\xa5\xab\xf7`\xbe\xd0\x03`\xa4\x931\xe1>\xf6c\xce\x99N\x98\xadWC\xc7b4\xde\x13\xfcv\x1c$\xb0\xd1;=\x8e\xc9s\x86\t(\xd7\x92;7+\xa8mC5"
    crypto.session.master_secret='\x87vhw\xa5\xcb\xe3\x0c\xfa\xdbD\x0f\x10C\x0e\x9ce\x0f\xca\xcd\x1d*\xbbk\xf6\x1c\xca\xc0{\xcdl\x9bW\x14\xff\xb6\xd7\xfe\xc8T\xed\x92HK5\x19\x86>'
    crypto.session.randombytes.client="U\xa6\xe4\xdb\x9a\x8d\x15\x01\x9f\xe4\xa8\x14\xb7\x15\xa4\x03s|\xfa\xd3+\r\xabor\xd7\xce\xdf\xc9'I?"
    crypto.session.randombytes.server='U\xa6\xe4\xdb\xef\xe1\xf9\x0f\xa6\x98\xdc\xdd\x03&\x80\x9c\xd5\x9b\x15J.k\x15\xcf\x8f\xbd\xe8\x08wL;('
    crypto.session.key.client.mac='\x8f]\xf9\x85\x91Q\xc0\xdd\x9b\x97\xe4\xa3%\x0fv[%;}\xe0'
    crypto.session.key.client.encryption='\x86\xd7\xc7\xe5\xee\x84\xc7#\xbd\xe0\x9cu\xbc\xec\xa9"'
    crypto.session.key.cllient.iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    crypto.session.key.server.mac='\xf3)<\xd9P\xdd\xb5 \xc5\x0cF\xfd\xb7O*\xfc\x0b\x1d\xc6\xaa'
    crypto.session.key.server.encryption='\x04\xf3\x04\x91a\x1c\xc2\xdf\x83C)\xe5\x1f~9\xbd'
    crypto.session.key.server.iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    crypto.session.key.length.mac=20
    crypto.session.key.length.encryption=16
    crypto.session.key.length.iv=16
>

```

##### SCSV Fallback Testing

socket stream example to test remote implementations for protocol downgrading attemps (following latest SSL POODLE attacks) - examples/SCSV_fallback_test.py

```python
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

```

##### SSLv2 dissection
```python
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
```

##### TLS Sniffer / PCAP decryption

TLS1.0 Session Context based decryption of RSA_WITH_AES_128_CBC_SHA for known private key 

```python

# python examples/sessionctx_sniffer.py 192.168.220.131 443 tests/files/RSA_WITH_AES_128_CBC_SHA_w_key.pcap tests/files/openssl_1_0_1_f_server.pem
* pcap ready!
* load servers privatekey for ciphertext decryption (RSA key only): tests/files/openssl_1_0_1_f_server.pem
|   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 length=0x200 |<TLSHandshake  type=client_hello length=0x1fc |<TLSClientHello  version=TLS_1_2 gmt_unix_time=120678007 random_bytes="Ua\xc1\\w22\xc4\x01s\x8d>\xc0\xd2\xa6\xe2\xb7#4*]#\xaf\x003\xa3'\xa0" session_id_length=0x0 session_id='' cipher_suites_length=0x76 cipher_suites=[49200, 49196, 49192, 49188, 49172, 49162, 163, 159, 107, 106, 57, 56, 136, 135, 49202, 49198, 49194, 49190, 49167, 49157, 157, 61, 53, 132, 49199, 49195, 49191, 49187, 49171, 49161, 162, 158, 103, 64, 51, 50, 154, 153, 69, 68, 49201, 49197, 49193, 49189, 49166, 49156, 156, 60, 47, 150, 65, 49170, 49160, 22, 19, 49165, 49155, 10, 255] compression_methods_length=0x1 compression_methods=[0] extensions=[<TLSExtension  type=ec_point_formats length=0x4 |<TLSExtECPointsFormat  length=0x3 ec_point_formats=[0, 1, 2] |>>, <TLSExtension  type=supported_groups length=0x34 |<TLSExtEllipticCurves  length=0x32 elliptic_curves=[14, 13, 25, 11, 12, 24, 9, 10, 22, 23, 8, 6, 7, 20, 21, 4, 5, 18, 19, 1, 2, 3, 15, 16, 17] |>>, <TLSExtension  type=signature_algorithms length=0x20 |<TLSExtSignatureAndHashAlgorithm  length=0x1e algorithms=[<TLSSignatureHashAlgorithm  hash_algorithm=sha512 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha512 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha512 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha384 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha384 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha384 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha256 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha256 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha256 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha224 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha224 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha224 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha1 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha1 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha1 signature_algorithm=ecdsa |>] |>>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode=peer_allowed_to_send |>>, <TLSExtension  type=padding (TEMPORARY - registered 2014-03-12, expires 2016-03-12) length=0xf0 |<Raw  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>] |>>>] |>
|   192.168.220.131 :443   => 192.168.220.1   :54908 | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 length=0x56 |<TLSHandshake  type=server_hello length=0x52 |<TLSServerHello  version=TLS_1_0 gmt_unix_time=1435009774 random_bytes='\x1d\xc0u!\xbd\xf9\xc3\xd9\xadmYR\xb4G\x93\xeacX\x88\xe1q/\x08\x16xp+$' session_id_length=0x20 session_id='\xb4X\xecfj\xfa\xa56F\xd8,\x07=\xb1:y\x12P\xc04"\xd4\xfe\x88eC}\xe1\xad]\xdf1' cipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NULL extensions=[<TLSExtension  type=renegotiation_info length=0x1 |<TLSExtRenegotiationInfo  length=0x0 data='' |>>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode=peer_allowed_to_send |>>] |>>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x3f5 |<TLSHandshake  type=certificate length=0x3f1 |<TLSCertificateList  length=0x3ee certificates=[<TLSCertificate  length=0x3eb data=<X509Cert  version=<ASN1_INTEGER[2L]> sn=<ASN1_INTEGER[13397879971383713459L]> sign_algo=<ASN1_OID['.1.2.840.113549.1.1.5']> sa_value=<ASN1_NULL[0L]> issuer=[<X509RDN  oid=<ASN1_OID['.2.5.4.6']> value=<ASN1_PRINTABLE_STRING['UK']> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.10']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\rOpenSSL Group']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.11']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\x19FOR TESTING PURPOSES ONLY']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\x1cOpenSSL Test Intermediate CA']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>] not_before=<ASN1_UTC_TIME['111208140148Z']> not_after=<ASN1_UTC_TIME['211016140148Z']> subject=[<X509RDN  oid=<ASN1_OID['.2.5.4.6']> value=<ASN1_PRINTABLE_STRING['UK']> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.10']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\rOpenSSL Group']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.11']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\x19FOR TESTING PURPOSES ONLY']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>, <X509RDN  oid=<ASN1_OID['.2.5.4.3']> value=<ASN1_BADTAG[<ASN1_DECODING_ERROR['\x0c\x10Test Server Cert']{{Codec <ASN1Codec BER[1]> not found for tag <ASN1Tag UTF8_STRING[12]>}}>]> |>] pubkey_algo=<ASN1_OID['.1.2.840.113549.1.1.1']> pk_value=<ASN1_NULL[0L]> pubkey=<ASN1_BIT_STRING['\x000\x82\x01\n\x02\x82\x01\x01\x00\xf3\x84\xf3\x926\xdc\xb2F\xcafz\xe5)\xc5\xf3I("\xd3\xb9\xfe\xe0\xde\xe48\xce\xee"\x1c\xe9\x91;\x94\xd0r/\x87\x85YKf\xb1\xc5\xf5z\x85]\xc2\x0f\xd3.)X6\xccHk\xa2\xa2\xb5&\xceg\xe2G\xb6\xdfI\xd2?\xfa\xa2\x10\xb7\xc2\x97D~\x874mm\xf2\x8b\xb4U+\xd6!\xdeSK\x90\xea\xfd\xea\xf985+\xf4\xe6\x9a\x0e\xf6\xbb\x12\xab\x87!\xc3/\xbc\xf4\x06\xb8\x8f\x8e\x10\x07\'\x95\xe5B\xcb\xd1\xd5\x10\x8c\x92\xac\xee\x0f\xdc#H\x89\xc9\xc6\x93\x0c"\x02\xe7t\xe7%\x00\xab\xf8\x0f\\\x10\xb5\x85;f\x94\xf0\xfbMW\x06U!"%\xdb\xf3\xaa\xa9`\xbfM\xaay\xd1\xab\x92H\xba\x19\x8e\x12\xech\xd9\xc6\xba\xdf\xecZ\x1c\xd8C\xfe\xe7R\xc9\xcf\x02\xd0\xc7\x7f\xc9~\xb0\x94\xe3SDX\x0b.\xfd)t\xb5\x06\x9b\\D\x8d\xfb2u\xa4:\xa8g{\x872\nP\x8d\xe1\xa2\x13J%\xaf\xe6\x1c\xb1%\xbf\xb4\x99\xa2S\xd3\xa2\x02\xbf\x11\x02\x03\x01\x00\x01']> x509v3ext=[<X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.19']>, <ASN1_BOOLEAN[-1L]>, <ASN1_STRING['0\x00']>]]> |>, <X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.15']>, <ASN1_BOOLEAN[-1L]>, <ASN1_STRING['\x03\x02\x05\xe0']>]]> |>, <X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.16.840.1.113730.1.13']>, <ASN1_STRING['\x16\x1dOpenSSL Generated Certificate']>]]> |>, <X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.14']>, <ASN1_STRING["\x04\x14\x82\xbc\xcf\x00\x00\x13\xd1\xf79%\x9a'\xe7\xaf\xd2\xef \x1bn\xac"]>]]> |>, <X509v3Ext  val=<ASN1_SEQUENCE[[<ASN1_OID['.2.5.29.35']>, <ASN1_STRING['0\x16\x80\x146\xc3l\x88\xe7\x95\xfe\xb0\xbd\xec\xce>=\x86\xab!\x81\x87\xda\xda']>]]> |>] sign_algo2=<ASN1_OID['.1.2.840.113549.1.1.5']> sa2_value=<ASN1_NULL[0L]> signature=<ASN1_BIT_STRING["\x00\xa9\xbdMW@t\xfe\x96\xe9+\xd6x\xfd\xb3c\xcc\xf4\x0bM\x12\xcaZt\x8d\x9b\xf2a\xe6\xfd\x06\x11C\x84\xfc\x17\xa0\xeccc6\xb9\x9e6j\xb1\x02Zj[?j\xa1\xea\x05e\xac~@\x1aHe\x88\xd19M\xd3Kw\xe9\xc8\xbb+\x9eZ\xf4\x0849G\xb9\x02\x081\x9a\xf1\xd9\x17\xc5\xe9\xa6\xa5\x96Km@\xa9[e(\xcb\xcb\x00\x03\x82c7\xd3\xad\xb1\x96;v\xf5\x17\x16\x02{\xbdSSFr4\xd6\x08d\x9d\xbbC\xfbd\xb1I\x07w\tazB\x17\x110\x0c\xd9'\\\xf5q\xb6\xf0\x180\xf3~\xf1\x85?2~J\xaf\xb3\x10\xf7l\xc6\x85K-'\xad\n \\\xfb\x8d\x19p4\xb9u_|\x87\xd5\xc3\xec\x93\x13A\xfcs\x03\xb9\x8d\x1a\xfe\xf7&\x86I\x03\xa9\xc5\x82?\x80\r)I\xb1\x8f\xed$\x1b\xfe\xcfX\x90F\xe7\xa8\x87\xd4\x1ey\xef\x99m\x18\x9f>\x8b\x82\x07\xc1C\xc7\xe0%\xb6\xf1\xd3\x00\xd7@\xabK\x7f+z>\xa6\x99LT"]> |> |>] |>>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x4 |<TLSHandshake  type=server_hello_done length=0x0 |>>] |>
<TLSSessionCtx: id=162830668
    params.handshake.client=<TLSClientHello  version=TLS_1_2 gmt_unix_time=120678007 random_bytes="Ua\xc1\\w22\xc4\x01s\x8d>\xc0\xd2\xa6\xe2\xb7#4*]#\xaf\x003\xa3'\xa0" session_id_length=0x0 session_id='' cipher_suites_length=0x76 cipher_suites=[49200, 49196, 49192, 49188, 49172, 49162, 163, 159, 107, 106, 57, 56, 136, 135, 49202, 49198, 49194, 49190, 49167, 49157, 157, 61, 53, 132, 49199, 49195, 49191, 49187, 49171, 49161, 162, 158, 103, 64, 51, 50, 154, 153, 69, 68, 49201, 49197, 49193, 49189, 49166, 49156, 156, 60, 47, 150, 65, 49170, 49160, 22, 19, 49165, 49155, 10, 255] compression_methods_length=0x1 compression_methods=[0] extensions=[<TLSExtension  type=ec_point_formats length=0x4 |<TLSExtECPointsFormat  length=0x3 ec_point_formats=[0, 1, 2] |>>, <TLSExtension  type=supported_groups length=0x34 |<TLSExtEllipticCurves  length=0x32 elliptic_curves=[14, 13, 25, 11, 12, 24, 9, 10, 22, 23, 8, 6, 7, 20, 21, 4, 5, 18, 19, 1, 2, 3, 15, 16, 17] |>>, <TLSExtension  type=signature_algorithms length=0x20 |<TLSExtSignatureAndHashAlgorithm  length=0x1e algorithms=[<TLSSignatureHashAlgorithm  hash_algorithm=sha512 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha512 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha512 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha384 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha384 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha384 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha256 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha256 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha256 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha224 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha224 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha224 signature_algorithm=ecdsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha1 signature_algorithm=rsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha1 signature_algorithm=dsa |>, <TLSSignatureHashAlgorithm  hash_algorithm=sha1 signature_algorithm=ecdsa |>] |>>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode=peer_allowed_to_send |>>, <TLSExtension  type=padding (TEMPORARY - registered 2014-03-12, expires 2016-03-12) length=0xf0 |<Raw  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>] |>
    params.handshake.server=<TLSServerHello  version=TLS_1_0 gmt_unix_time=1435009774 random_bytes='\x1d\xc0u!\xbd\xf9\xc3\xd9\xadmYR\xb4G\x93\xeacX\x88\xe1q/\x08\x16xp+$' session_id_length=0x20 session_id='\xb4X\xecfj\xfa\xa56F\xd8,\x07=\xb1:y\x12P\xc04"\xd4\xfe\x88eC}\xe1\xad]\xdf1' cipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NULL extensions=[<TLSExtension  type=renegotiation_info length=0x1 |<TLSExtRenegotiationInfo  length=0x0 data='' |>>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode=peer_allowed_to_send |>>] |>
    params.negotiated.version=TLS_1_0
    params.negotiated.ciphersuite=RSA_WITH_AES_128_CBC_SHA
    params.negotiated.key_exchange=RSA
    params.negotiated.encryption=('AES', 16, 'CBC')
    params.negotiated.mac=SHA
    params.negotiated.compression=NULL
    crypto.client.enc=<Crypto.Cipher.AES.AESCipher instance at 0x9bbddec>
    crypto.client.dec=<Crypto.Cipher.AES.AESCipher instance at 0x9bbde0c>
    crypto.server.enc=<Crypto.Cipher.AES.AESCipher instance at 0x9bc4b2c>
    crypto.server.dec=<Crypto.Cipher.AES.AESCipher instance at 0x9bc4b4c>
    crypto.server.rsa.privkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x9b6ed8c>
    crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x9bbde6c>
    crypto.server.dsa.privkey=None
    crypto.server.dsa.pubkey=None
    crypto.client.dh.x=None
    crypto.client.dh.y_c=None
    crypto.server.dh.p=None
    crypto.server.dh.g=None
    crypto.server.dh.x=None
    crypto.server.dh.y_s=None
    crypto.session.encrypted_premaster_secret='\x08\xa9xP\xf3\xdb\xfc\x8b,\xc0C^N\x96ALQ\t\xabW\xcb\x9a\xe4\'\xa96\xb8y\xf8\x1d\xda\x7f\x97Q\x804\x12\n\xe4\xce/|\xa3\xbfS\xe8\xd3\xf3\x12\x83n{\xab\x99\xe2\xff\xb2G\x13J\xff\xa4xC\x12\x03 \x91\xe2\xa9I\xee\xaeW\xe5\xa4k\xc4^\x95\x8e\xba\r#\xdf\xa2JD\xca\xa0\x98S\x933*<\xc1\n\x18\x1f\xd9\xe4\xad\x82\xb6\xea\x9c\xb8\x14\xa61\xb1#1\xaf\x16\n\x9b\xf9f\xccm\x16\x88`X\xd4\x0f\xd9\x111\t\x1b\xb3\\\xcb\x90@\xa0\x8dJ\xf9b\xe4k\x00\x0f1\x0e\xcb\xc3=G^??\xba\xee\xc3\xeb\x16\xe8\xf9\xd6\xdf5e\xb8\r5)\xc7\xc1\xf3\x1d\x85\x181:/\x1d\x16j\xdcS`E\xa7\xc2D"\xabp\xef\xd96\xc1\xf0.\xe7[\xa5.1}\xb1\x8f\x00"g\xf9\x89\xdc\xae\xbepEq\xb0,U\x0c@-[_\x0e\xfd\xc6\xb0Y@\x90\x18\xe4\x1c\xb1\xf3\x9a\xe9\xd9\x80P\xd8\xa9\x01Z\x9d\x000\x95\xbb\xddf\x13\xc9'
    crypto.session.premaster_secret='\x03\x03vlW\xed[\x83\xffZ\xa5\xc4+\xf2\x92c\xd4\x94\x90\x86\x95\x90\xdf\xfe\xea\xf1\xb2q\x03\xecr\xb8E\xadf\xf2Sgx\x1f\xf6\xdcK\xac\x00\x8c,0'
    crypto.session.master_secret='\xb9*\x18\x1e\xc8\x1aF\x8f\x1dO\xeb!\xddp\xb0\x9cE\xbb=\xc6\xb2\xf3\xcfK\xbfm\x8a\xc1\xd6\x16\t\xf9+\xa7>fR\xda\xf2U\xaf\xac\xf0\xe1l(j\x8d'
    crypto.session.randombytes.client="\x071fwUa\xc1\\w22\xc4\x01s\x8d>\xc0\xd2\xa6\xe2\xb7#4*]#\xaf\x003\xa3'\xa0"
    crypto.session.randombytes.server='U\x88\x82\xee\x1d\xc0u!\xbd\xf9\xc3\xd9\xadmYR\xb4G\x93\xeacX\x88\xe1q/\x08\x16xp+$'
    crypto.session.key.client.mac='\xce)\x08\xc5\x07\xfcAC?{\x05\x13\x89"\xc8R\xc4\x10\x97/'
    crypto.session.key.client.encryption='\xc0\xe7K\xf3\x1d\xa37\xe3v\xf7\x95\x06\x98/\x98\x84'
    crypto.session.key.cllient.iv='\t\xc5\xe0~%\xb9+\x8aIg\x04lCIr\x0b'
    crypto.session.key.server.mac=' unp\xb9\x98\x10-\x8c\xf7\xa3\xaf\xa0S\xfaP\x13\xaa\x8a\xdf'
    crypto.session.key.server.encryption='\xbd\xc0\xd4\xa1L\xfa\xce\xc8\xcc\x05\n#\xf4(\x11\xa8'
    crypto.session.key.server.iv='5\\\xf1\xe2\xb1\x99\xf6\xbaI\xa6\xd0\x87k/\x7f\xd2'
    crypto.session.key.length.mac=20
    crypto.session.key.length.encryption=16
    crypto.session.key.length.iv=16
>
|   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 length=0x106 |<TLSHandshake  type=client_key_exchange length=0x102 |<TLSClientKeyExchange  length=0x100 data='\x08\xa9xP\xf3\xdb\xfc\x8b,\xc0C^N\x96ALQ\t\xabW\xcb\x9a\xe4\'\xa96\xb8y\xf8\x1d\xda\x7f\x97Q\x804\x12\n\xe4\xce/|\xa3\xbfS\xe8\xd3\xf3\x12\x83n{\xab\x99\xe2\xff\xb2G\x13J\xff\xa4xC\x12\x03 \x91\xe2\xa9I\xee\xaeW\xe5\xa4k\xc4^\x95\x8e\xba\r#\xdf\xa2JD\xca\xa0\x98S\x933*<\xc1\n\x18\x1f\xd9\xe4\xad\x82\xb6\xea\x9c\xb8\x14\xa61\xb1#1\xaf\x16\n\x9b\xf9f\xccm\x16\x88`X\xd4\x0f\xd9\x111\t\x1b\xb3\\\xcb\x90@\xa0\x8dJ\xf9b\xe4k\x00\x0f1\x0e\xcb\xc3=G^??\xba\xee\xc3\xeb\x16\xe8\xf9\xd6\xdf5e\xb8\r5)\xc7\xc1\xf3\x1d\x85\x181:/\x1d\x16j\xdcS`E\xa7\xc2D"\xabp\xef\xd96\xc1\xf0.\xe7[\xa5.1}\xb1\x8f\x00"g\xf9\x89\xdc\xae\xbepEq\xb0,U\x0c@-[_\x0e\xfd\xc6\xb0Y@\x90\x18\xe4\x1c\xb1\xf3\x9a\xe9\xd9\x80P\xd8\xa9\x01Z\x9d\x000\x95\xbb\xddf\x13\xc9' |>>>, <TLSRecord  content_type=change_cipher_spec version=TLS_1_0 length=0x1 |<TLSChangeCipherSpec  message='\x01' |>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSCiphertext  data=',\x8c\xecA\x83\xa7\x8c\xce\xe3\x9e\xb20\xdf5\x92_\xea\x1f\xe7\xda\x16\xb8\tQ\xbbs\xa0%/P\xd9\xb1|\x80\xbf\x0bS/U\xa0\x8b\t\xae;\x9a4\xe9\x08' |>>] |>
|-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=handshake version=TLS_1_0 length=0x106 |<TLSHandshake  type=client_key_exchange length=0x102 |<TLSClientKeyExchange  length=0x100 data='\x08\xa9xP\xf3\xdb\xfc\x8b,\xc0C^N\x96ALQ\t\xabW\xcb\x9a\xe4\'\xa96\xb8y\xf8\x1d\xda\x7f\x97Q\x804\x12\n\xe4\xce/|\xa3\xbfS\xe8\xd3\xf3\x12\x83n{\xab\x99\xe2\xff\xb2G\x13J\xff\xa4xC\x12\x03 \x91\xe2\xa9I\xee\xaeW\xe5\xa4k\xc4^\x95\x8e\xba\r#\xdf\xa2JD\xca\xa0\x98S\x933*<\xc1\n\x18\x1f\xd9\xe4\xad\x82\xb6\xea\x9c\xb8\x14\xa61\xb1#1\xaf\x16\n\x9b\xf9f\xccm\x16\x88`X\xd4\x0f\xd9\x111\t\x1b\xb3\\\xcb\x90@\xa0\x8dJ\xf9b\xe4k\x00\x0f1\x0e\xcb\xc3=G^??\xba\xee\xc3\xeb\x16\xe8\xf9\xd6\xdf5e\xb8\r5)\xc7\xc1\xf3\x1d\x85\x181:/\x1d\x16j\xdcS`E\xa7\xc2D"\xabp\xef\xd96\xc1\xf0.\xe7[\xa5.1}\xb1\x8f\x00"g\xf9\x89\xdc\xae\xbepEq\xb0,U\x0c@-[_\x0e\xfd\xc6\xb0Y@\x90\x18\xe4\x1c\xb1\xf3\x9a\xe9\xd9\x80P\xd8\xa9\x01Z\x9d\x000\x95\xbb\xddf\x13\xc9' |>>>, <TLSRecord  content_type=change_cipher_spec version=TLS_1_0 length=0x1 |<TLSChangeCipherSpec  message='\x01' |>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSPlaintext  data='\x14\x00\x00\x0c\xc2\xc7\x91Hv\x8d\xddf\xbd\xa2\xd3\xbe' mac="#v\x9a\xe2\xb7osL[\x9ew\x0f\xcf\x9b\x13do'kC" padding='\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>] |>
|   192.168.220.131 :443   => 192.168.220.1   :54908 | <SSL  records=[<TLSRecord  content_type=change_cipher_spec version=TLS_1_0 length=0x1 |<TLSChangeCipherSpec  message='\x01' |>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSCiphertext  data='\x917\xacq\x0f\x8a\xe6\xcd\xc7\x0c\xe8\xe9(\xe2\xda\xbc\xe2\xcd\x8cbP9$\xc5vGO\xcc\xb1_\xc8G\x14Z\xd4\xd6:\xfa\xc4\xdd\xcd\xdaH6\x08\x18\xbb\x98' |>>] |>
|-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=change_cipher_spec version=TLS_1_0 length=0x1 |<TLSChangeCipherSpec  message='\x01' |>>, <TLSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSPlaintext  data='\x14\x00\x00\x0c1\xa9\xd7 v\r\xe1\x0e\xa4M2x' mac='\x9f\x81w\x94\xd1\xd9pe\x86\xe1f\xf0\xce\x803s\x9by\x1d4' padding='\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>] |>
|   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1_0 length=0x20 |<TLSCiphertext  data='\x81\x05\x1f4V\xc1h\x85\x955\xc4\xa1=Q"GD\xae\x8bW\xad\xda\xa3?/\xc8\xe0\xbbR\xc0u\xde' |>>, <TLSRecord  content_type=application_data version=TLS_1_0 length=0x70 |<TLSCiphertext  data='\xaa\xc0\x05hT\x1a\x9a\xc5\x10<\xcf#{v\xefor\x04\x9e\xf3\xb9T\xde\n\xb5\xb0R\xfa\xd70[.\xb2\x1e\xdc\x94\xccq\x04\xb7\x8e\xe3[\xcb=\xb1\x0c3\xd8\x82\xec\xa7\x97\xf2\xfe\x1f\xcdp\x94\xc5\x06]\xf0\xee\xadZ\xb4\xe7L<T\x99\xf8\x8a$\xafK\xd0\xd5\xc3\xa3\xc4\x89 \xeb\xef*0\x82\xd2\x8aK5\xbez$\x942/\xb2\x81\xe3\x90\x90\x98\xb3\xf6\x9b\x1e\x8e\xa0\xcd' |>>] |>
|-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1_0 length=0x20 |<TLSPlaintext  mac='l\x0c2\xb0\xe4D\x87@n\x1dM\xfdRP\x94\x95\xadp\xa5\t' padding='\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>, <TLSRecord  content_type=application_data version=TLS_1_0 length=0x70 |<TLSPlaintext  data='GET / HTTP/1.1\r\nUser-Agent: curl/7.37.1\r\nHost: 192.168.220.131\r\nAccept: */*\r\n\r\n' mac='\x96\xee\xffa\x13\xd3\xa6\x97C\xa2\xd0y\xf1\x00r(\x07\x12\xb3\xff' padding='\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c' padding_len=0xc |>>] |>
|   192.168.220.131 :443   => 192.168.220.1   :54908 | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1_0 length=0x20 |<TLSCiphertext  data='c\x12\x0f\xcf\x80\xca{\xd1\xa97\x94\x0b\x8cP\xab\xcc~/,\xea\x9f\x12\x0b\xd5\xf94lR\x7f\xa6g\xf3' |>>, <TLSRecord  content_type=application_data version=TLS_1_0 length=0xb40 |<TLSCiphertext  data='\x1a\xbf+_Y\x17\xe0\x10\x939\x04im\xf3M\x944\xa6=\x16\r\xdcv \xae\xfe\xf0\x14\xce\x86\xb8\xc5R\xb1\xf0\xcd\x93w\xe1X\n\xaf*(0+t\xe7S\xc7\xe2\x15\x0f\x9f[\xac\x8c\xfbW\x05Zv1|\xdf\xe9\xddT\xf2\x02\x92a\x9f\xb2\x941\xf4\x96\xd0\xe0\xf2B\x90\x04\xcc\xcd2\xbc\x96\xb0\xee\x16\xab\x1cy\xde=\xee\x01\x9cc\x92gp\x94\x98\xa6\xe4\xb6\xc6\xce\xefTr\xe8-\xde\xeaI\xf0\xf4bJ\xa3U\xefTg\x05\x83\xfaZ\xc8 Q\x02\xba\xb1\x9e\x95\xb5\xf5\xa8\xe7\xd7\xbc\xfd\xee\xccI\\\x1b>]ew\xaeX\xceJ\tO\xeb\x88\x98\x82}\xcfj5r\tG\x86\xd9.\xad\x80\xbd\xd0 P\x92\xcc\x18;\xff]e\x00^[\xd6q\xf2w\xd9]\xe7\xde\x1c}\xd4B\xf1x\xf8\x966\x81,\xea\xb8#\x1d\x1b\xc9\xberTQ\x99{]\xeb\xba\xaco\x13>/8a\xb3\xc4\x0f\xe2\x98\x89\xc5\xfbC\xec\xe1fJj\x8d\x10\xe0\x95l\xf8j\xc9\xdbCw\xcfS\x92e\x0cX|\xb9}\xcd([[d-\xf9\x99\xc2Xe\xe7\x92v\xef \xe5}g;\x13\x93 R\x90s\xf7\x08\xee\xdav\xe6\x17\x84\x8fbZ\xa3\\#\xba\x7f\xfbzd\x9dF\xdeo\xe8\x8b\x8c\x97,Q\xeb\xc9K\xa1\xb0\xe6%B\x1cJ9(r%\xff\xc2\xe7\xbf\x9c\xf3\xa2\xe1D\'\x11\xbf\xfe\xeb\xa8\xb9^\x8e\x9bY\x9e\x1a\x95\xb0F\x15\x14\xd0\xf9)\xc9bW\xd2\x16\xbbb\x14+\xe1\x92=cl{P\xfc\x10\x10/\xf7]20\xe0?\xc4\xbb\x85\xc4\x02ui\xa2\xad\x8cq41\x16}\xcf\xff\x00\x85\x9f\x03\x8b\xf0\xbe\x19\x19\xdfuB$8\xf2\xc1\xa6S\x88\xc3\xc8\xbd\xb4\x87I\xeeA\xf0\nS8mj6\xc8\x0b*\xc0\x9e-\xc2\xcf\xee\xd9#BG\xb2\x1d\xfd*bu\x85\xf7\xe5\xfb\xb7\xe1\x19\x1e\xb5\xeb\xbe\xf7\xf9\xad\x91\xf0-j\x9b\xf1\x89\x8c]8\xd2\x99m\xbd\x00\x86\xf5\x18\x19H\xf80\x1fG\x01^R(\xc7\xd23z\xcf\xbf\x16\x87\xcaR\xd2\xc6\xdc\xde\xc8R-\x1aAF=\x16\xe2\xd6\xb2!I\xa8L\x98\xe2*_H\x9ad?\xed\xc5t\xcck\xf9\x819\x92\xa5\x8e\x97t{*\xd4\xb1\x8b\xa4\xe5 By\xd6\x9e\xbe\xfaq\xf9@u\xf1"\x8a\xf2\x1f\xe8\xdc\x9cEU\xc5\xa9x\\\xd4\xeb\xd6\'\xb6%\x8a\x18;O\xb9)\xa7\x9c\xe4\xd8q\x1d\xcf\x80\xa0\xb9_C$\xd3\xcd\xadI\x1b\x1a\xcc\x0f\xc4F\xb7q\x94b\xc9I\xd8\x8a\xf3\x83\xb1i\x18\xd9\x94>,Y\xe2\x1aD\xee-D\x1c\x1e\x17\xe7\xc4\xace\xc0\x7fFTk\x8aL\x08\xfe0M>\x87\x0e\x19B\xe2\xad\x12Q!\xb7\'\x9drRZ\x9a\xe5\x01q\x05q\x15\xb4\xad\xfa\xa5\x06\x01\xcd\xa7\xf2\x90\'\xff#I\xab\x81b\x85\xbb \x08M\x0f\x80GNJ\xd0\x1e\xe2\xa4\x04\xd8\x12\xb1@\x88\xbf\x9f\xef3N\x97\xd8V>\x9d#\xee\xed\x9f\xac\xec\x06\xd1\xb9\x99n\xd5\xadT\x15\x9cY\xa9|\xa8\xc1P_x1N\x0c\x00q\xef\x90\x8evT\xf1!\xabC\xa9\xb0Z\xdd\xafn\xf2\x97\xd5\x85\xaer\xd7\xd0\x92\x0e\xda91-\xeb\xb8zJ\x8b\xf1\x04\xadF\xa1\xa3\x82\x93\xceU\xdbf\x97\xc2$T2\x9c\x1b\xc8\x86\x18A\xf5FyW\xf8\xd0\xba\xb8\x12\xb8\xdeB\xf5\xcfz \xfc\xdd\xd2p\xc1\xf9\xb1\x8f \x9d^\xa3l&1u\x15\x9a~\xad=\x03f3y\xc4\xeau!\xb3 J@\xdfi\xd6\x0b\xd3\xfeA\x9b\r\xa4PB\xc4Qy!\xe0T\x14)\xfdb\xb2\x99w\x90\xde@\x0eg\xbb\xa6\r9\x96rd9\xe6\x868\xbe\x84/\t)gxRM=\xe4\x06\xa1\x17\xd7\xfdP\xf4SyS1\x80\\\xf5\xc5%\x13\xdf\xb5\xdd\xf2[\xc9}\xfb\x95\x9e\xa0v\xf4\xc1\xe0u\xdc\x92\xd5\xc0u`\xf15\x95\x05\x92ja\xe3\x80w\x95+\xc4c\xc8Kf/\xaf\xbd\xc4\xc9e\xba\xc4\xb9\xde\x9d\x1b\x96\x9d\x9b \xd6]\xe3Q\x1e\x0e\xb8X\xcb\xcb\xb1\x06\xa6!\xd0\x96Cw\x8b$\\\x87k)Od\x88\xdf\x0b\xaa^\x8f"\xb7\xaf\x07\xb6\xd7~\xe9H\xeb\x90\x88\xa9\n\x85\xcc\xad\x02\x04B\xd9\xca-\xffk&7\x98\xa3\xaf\xddsm\x0fr\x05\xf9=\x12^\xcf\xca\x92\x1cwa\x9fm:\xfd\x97\xdeA\xfb\x019\'\xa8ce>\xc5j\xd7\xf3\xf4\xb5\xb5w#\x96\x1c\xcc\xc4~\x08\xab\xde\x9f\xfe\x9a\xd7T\x90%q\x1c\x17\x95Q\xe0n\xf46\x97\xdf\xa7q\x1b:\x88\x98\xfbxu\x8d*~h\r<\xcf\x7f\xb0\xd8\xd6\xca\x8b}\'G\xdfj\xfd7\x0e\x0fl\x9au\x94\x98K\xd7e\xd1\xc8gAYI\xcaUDZO&\xd9!E\xbe\xae\x16\xda\xed\xce#\xaa\xc5\x15\xcb\xc4K\x9b3\xb9\xd9F\xe3\xfa\xc4/\x1fs\xc8\x8c\x11\xde\xd8w\xd9\xee\xd6=|\x12 ?\x9f\xc8\xc2\xa9\xd6\x8b\x0e\xc2\xeaIS\xb1\xed\xe5\xba/(\x81\xdb\x87#\r\xe6\xe1*\xd22\xe8\x9f\xc3\xb0\x04\xd8\xcfv\xb8\xf2\xbb\xae\xf1\xf9\xdd\xa5m\xa6\x93\x92\x9a\x1ce\x93S\xadln\xe3\xa2\xc0\x82M\xe3:\xc7\xaa\x9e\xd4\x99{%9\xd5\x1bw\xd4c}\xd7p\xaf\xee\xadx\'H\xcc\xff\xab\xc8\rH\x1d\xf9\x0e\xee<Z\x9f8B\xae\xb6#\xbb\t;P\xb5D\xe0\x89BZ\xdc\xf0\x07\x9f\x95\x10?>\xd1\x17\xa2g\xaa\xde\xf6t!{\xd7\xc7\xf5b\xe4\xf45\xa8(\xd0\xdc\xbf\x86\xff\xf9\xc9\xfc\x9b\xc2\xe2@\x0b\x8bm\x06\x98@\xfa\x06;\xe0\x80\x86\xbf\xf9\x0b\x03\x1f\xfb\xaf\x03^\x06\xb1/0\xb2\xcb_l7\xa6XM\xa2\xbb"\xcbQ`\xa1\xbf_5\xc0s\x9f\xfc\xf3\xb2\xe0\x14\xb04\xa8\xe2\x8eck\xfer\xe2\x81\x8a\x9a\xf2\xbai\xd6\x13G\x8b\xe4}</\xe3\xd9=\xdb\n\xc2\xa1\xd2A\x99\xd6r\x87t\x14rf\x1eo\xd22\xe0\x1f\xd4t \xfaJ\xa5\x92\x1aZ\xba\xc0|\xca<O\xa5\x8f\xfd\x14\xf1T5\x02VX\xbea.\x98q\xf9\r\x15,\xe4\xc6g\xf2\x83\xf63Az_ef\x1d\x95,\xc43 \x16E\xca9b\x83JAa\xd5?\x0b\xf0\x7f\xfeY\xa1\x04>\x19:D\xa2\x06?\xf4\xde\xcd\xe9I\xba\x9bd\x8f[~\xd0\xff\x80w\xf1/\xfb|\x08\xb3\x15\x98\x9e,\xd7lH\xc4&Z9Q^\x1e\xbf\x1c\xdbt\x00\xbe\xaf7\xa9\'^MH\xf1\xa3\xd7W[\xbf\x9b\xe0\x00\xce\xa3\x18\x1cz\x1f\xeaV?\xab\x8d-j\xab\xaf\x80\xab\xeb*\xb66\x1d\xea\xcf\xc1>\xdap\x14\x83\x02@\x91q#\x9f\xa7\xa1\x88\xd6\xbe\x97#\x8e\x08\xd8\xc9\x0cd&9.\xb0\x9d\x13\x03\xe2N<\x0b\xdf\x95\x9e\xa9\xe5R\xac\x1201\xb0"\xe8v]\x89\x0ez~\x1de\x91\xa6\xcd\xf0\x7f\xd7X8/Wv\x99\xe9\x16\xaf\xae\xf8\xca\xd9\x8a\x1d\xe1\x9c\x92\xde\x89;\xb5\x90\xc0Y\xf3\xa8\x9d2\xe8|\x02\xe0\xb1\r\xf5\x99N/\x16\xf1ky\xfc\xb5\xf4\xf5\xc3VQ=k\xee\xb8\x8fg\x9c,\x85yu\x05C\xc3\xe5!\x14>\xee,(y\xd8\xfe\xbf\xb9+uz\x1f"/6\x1e4i\xcf\xc8E\xebS\x1dp\x15\'\xce\xdf\xf3\xd7f\xd9\xd5\x18}\x14t\xd2VD\xf8-\x13\xba\xc2\xf6\x18\xfe\x9c\x10\x15_\x80\xffE~g\x96a\x91\xaf\x1f\x8a1\x12A\x05\xa6T\x01\xa0e\x9e\x0c\x9b\x9b\xc2\xd3\xd7\xf6k\x9a\x98\xdcxj^\x04q\xfb\xfca\x8am\xeb\xfeY\xd3\x06D\x15d\xc2\x1b\\M\xb1F\x0eu\x16\xf17\xdcg\xd8\nk\xe8n\x1d\x8c\xb1%\xb7\x8bl\xc0]F\xf4X\xe7\x8fE3K\xe3\x06\xa0d\x08\x98\xb4\xb8\x0c\xa7\xc2\xa3O\x93\xcc\xc2PC\x86J\xfd\xba\xd0#\x8c\xcc\xe1\xf6\x97F\x19)\xf0[\x8fR\xe2\x1aE\xb6\xca\xfe\xc9e+~\xaa\xd4\xf0\xb1\xef\xfd|\xa8\x15__U\x87\r\xae\xf8\x97\x92\xd19\x81s?U\x01\x01\x9f\xe0&\x9f\x99\x87\x7f\x8a\x84\x08n]\xc4\x00\xd6|\x1e-\x83\x90\xaf\xcf\x9a\x04\xff\xccH\x0c\x92\x7fuG\xf0n\x9f\xc7a\xec8\x8a\xf7|NI\xcf\xca\x18d{*\x86v\xfe[F\x8b\xc0\xcd\xa2+\\\x9b.z\xf1\x1b\xe6G\xe1lscV\x00\x87\x9e\xf1\x93\xb5\xe9\xcb\x164\x140g\xd0\xb9\x1d5\xc7\x7f/\xdc\xb6{|\xcb\xef\xbe\nT\xcf\xee\xa3e\x1eI\x1eIj\xbe]\xfe\x9d\xeb$\x19\x15\xe6\xdb\xb3\x17>\xf0\xb5\xc6\x9b\xff\x95\xb1\xa8mp\xec\xcb;\x8aM\x11&\xaf\xa3\xe6\r}\xc6K\xd9w\xe3\x99\xc4\rQ\x93A.\x19\xb1:\xec\x1e\xbd{},\x1f\xfe\x10\x984f.r\xd3\xd3\xc7\x12\x07\x9f9\xcc\xb6\xc5,\xe5\xe5l#\x08`\xa8\xa0\x94#\x17G\x15\xdf\xd5\x8c\x0c\x7f\xe3\x10\xe9\x85K\x9d\xf0\xa3\x9a\xf3\x85\xf9\xce\xbc*h\x10\xc2\xf9\x8c/\r\x84\xf5\xdf%{iI7&\xf6\x08\x14M]y\xe9\xb0VH\xe3\xc8\xe0Z\xeb@\xd4\x8b\x13\xb8\xb8\xf7\xa9\x01\xc4\xf6\xfb|\xe3\xe8Z*\xc01\x1aJ\x16\xfa%?:;N\xf9\x08\'\xfd]T\xcd\xf8Ey\xc6\xd8"@cq>\xa6\x12d\xbb\xd2\x92uw:#\xe2\xaf\x19\x01\x7f\xe92X\x8f\xad\xe2hO\xf6\x14\xc2c\xee\x8a\x08W$\xd2\xa5\xfb\x8f=\x1et[~\x07\xcf\xe0kW\x8e\xfdi\xa7d\xdd\x186\x9e\x05\x16\xd1\xa6\xa7\xe7V\x83\x0e\x15\xda`}\xa5\xc9\xcbM\xc3\xff\x15\xa0\x9bt\xb9\x8cWwL\x91\xbd\x00\xcdA\nK\\K/\xd2~p{\xf6\xe4\xaav\x07X\n\xef\xfe\x85\xcc\xc73\xde\xb9\x1d\xf0\x82R\x81S9\xddR8\xf34\xb4q\xe9\x12DY\xa9`\xbb>\xd3O\'\xd6\xe4\xb6"\xc2\x08h\xf3\xc3\xf1\xd5l\xe4\xf5,[\xa0-?\x9b\x12\x99\xaf\xb5\xd30\xc6K\xd3\xf0A\x93e\xf9\xf3\x07\xe0\xe2\x9b\xc3)\x00\xac6\xc7\xc4\x1e\xd3Kd^\xe8RN.\xf9\xe8\xc0\xf6\'\x1ag\xa7\xaa\x80\xe7\x8e\x1bMQ\r\xf9m\x14\xe8\x9f$\x1a\x8e\xc5C"\x8a\x0c\xa9\xc6\xe4\xe9\xf4\xc6Sz%L\xe5\xb6f\x86\x9e\x03b\x08\xb0\x86\xc2\x1b\xe4\x9b\x1f\xfb\xa8]fb$\xae\xb3f~%\xa6L\x7f\x90\xacTX\xddD{\x16\xb0\xab\xc5\xfe\x86|w\x82\x89\x12\xdf\xc0\xa6\xc2\xc7\xcf\x9b\xea\xa8\xd4\x99\xea\xb7\xd4J\x9c\xb7\xcd\x10\xa5#\xd8>\xcde\x9a\x9f\x10\xef)\xe1\xfb,\xf3\xee0\xa9\xa4\xe2f\xa5_y\xa7\xb6\x8b)D\xcf\xd4\xcc\xd8\x9d\x1f(\xbb\xec\\\xe2\x04\x90\xd7f\xfe\x0c\xc9\xdc\xbf\x8d\xd1\x1c\xca\x93\xae0"\xcc\x01m\xe8\xe4 R\x8c\xc6.v\x8c\xdc\x98\xbc\xe5\xf4\xc8\xaa\xc2\xc6\x11i\xa7\xcc\xc9\x10\x9c\xeb\x96\xc4\xd4\xd0\xd0C\x1d\xd5\xf5\x17b\xdc\xb7\x10E\xc9t\xb7\x82\xac\x9bh\xdc\x97W\xa6W\xa8G\xfa\'\x81\xaf\x12\x9b\xb8\xc2\xac\xdb\xad\xda\x86\xde\x0cVc\xea\xfe\xbb-?:\xbb\xf4|\xb1yi\xfb\xafw\xed\xa3]:y(\xa7\xe9etN\xf9cG\x1dux\xad\\\x8c\x84\xe11\xd5\x0e\x14\xcd;ex\x02\xeem\xe8\x0b\xf3\x9b%\xaf\\\x98\x86v\xfenV\xc4\x8fq\xe7J$j\x9f\xb8\x9b\xf4\xa91\xd7\xf2\xc2\x0f\xf1\xd8\x8a~\xee\x17\xa4\x05\x7f\x0ce-O\xd6\xa9\x95\xa3\xe9\xebu\nd\xdc\t\xaa~OU\xd8\x8c\xfa\xbb@+\x84\x16X\x83\xe6\x95K\x83U\xf8~\x07\r9\x8b2\xaery\xe6;\xcbT\xaa\xff\xa6X\xbb\xd8qsO\xe6\xd5\x04V"\x96\x8d\x87\x92\xbd\x90\xa4\xbb\x80\x96\x1dG\xb2NDzJBt\xa9\xf8\xcc\xf5\x8c\x1e\x11fP\xba\xbe\xf64"s\xd6$\xc9T\xda)\xd7\xe5\x19\x8f\x82m0' |>>] |>
|-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=application_data version=TLS_1_0 length=0x20 |<TLSPlaintext  mac='\xde\xaa\xce\xca\xb0\\\x0e\x86J\xd2\x81(7\xa7\xf3\x83x\xc1\xe1\xd5' padding='\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' padding_len=0xb |>>, <TLSRecord  content_type=application_data version=TLS_1_0 length=0xb40 |<TLSPlaintext  data='HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n<pre>\n\ns_server -accept 443 -cert openssl_1_0_1_f_server.pem -tls1 -cipher AES128-SHA -www \nSecure Renegotiation IS supported\nCiphers supported in s_server binary\nTLSv1/SSLv3:AES128-SHA               \n---\nCiphers common between both SSL end points:\nECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384   \nECDHE-ECDSA-AES256-SHA384  ECDHE-RSA-AES256-SHA       ECDHE-ECDSA-AES256-SHA    \nDHE-DSS-AES256-GCM-SHA384  DHE-RSA-AES256-GCM-SHA384  DHE-RSA-AES256-SHA256     \nDHE-DSS-AES256-SHA256      DHE-RSA-AES256-SHA         DHE-DSS-AES256-SHA        \nDHE-RSA-CAMELLIA256-SHA    DHE-DSS-CAMELLIA256-SHA    ECDH-RSA-AES256-GCM-SHA384\nECDH-ECDSA-AES256-GCM-SHA384 ECDH-RSA-AES256-SHA384     ECDH-ECDSA-AES256-SHA384  \nECDH-RSA-AES256-SHA        ECDH-ECDSA-AES256-SHA      AES256-GCM-SHA384         \nAES256-SHA256              AES256-SHA                 CAMELLIA256-SHA           \nECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA256   \nECDHE-ECDSA-AES128-SHA256  ECDHE-RSA-AES128-SHA       ECDHE-ECDSA-AES128-SHA    \nDHE-DSS-AES128-GCM-SHA256  DHE-RSA-AES128-GCM-SHA256  DHE-RSA-AES128-SHA256     \nDHE-DSS-AES128-SHA256      DHE-RSA-AES128-SHA         DHE-DSS-AES128-SHA        \nDHE-RSA-SEED-SHA           DHE-DSS-SEED-SHA           DHE-RSA-CAMELLIA128-SHA   \nDHE-DSS-CAMELLIA128-SHA    ECDH-RSA-AES128-GCM-SHA256 ECDH-ECDSA-AES128-GCM-SHA256\nECDH-RSA-AES128-SHA256     ECDH-ECDSA-AES128-SHA256   ECDH-RSA-AES128-SHA       \nECDH-ECDSA-AES128-SHA      AES128-GCM-SHA256          AES128-SHA256             \nAES128-SHA                 SEED-SHA                   CAMELLIA128-SHA           \nECDHE-RSA-DES-CBC3-SHA     ECDHE-ECDSA-DES-CBC3-SHA   EDH-RSA-DES-CBC3-SHA      \nEDH-DSS-DES-CBC3-SHA       ECDH-RSA-DES-CBC3-SHA      ECDH-ECDSA-DES-CBC3-SHA   \nDES-CBC3-SHA\n---\nNew, TLSv1/SSLv3, Cipher is AES128-SHA\nSSL-Session:\n    Protocol  : TLSv1\n    Cipher    : AES128-SHA\n    Session-ID: B458EC666AFAA53646D82C073DB13A791250C03422D4FE8865437DE1AD5DDF31\n    Session-ID-ctx: 01000000\n    Master-Key: B92A181EC81A468F1D4FEB21DD70B09C45BB3DC6B2F3CF4BBF6D8AC1D61609F92BA73E6652DAF255AFACF0E16C286A8D\n    Key-Arg   : None\n    PSK identity: None\n    PSK identity hint: None\n    SRP username: None\n    Start Time: 1435009774\n    Timeout   : 7200 (sec)\n    Verify return code: 0 (ok)\n---\n   1 items in the session cache\n   0 client connects (SSL_connect())\n   0 client renegotiates (SSL_connect())\n   0 client connects that finished\n   1 server accepts (SSL_accept())\n   0 server renegotiates (SSL_accept())\n   1 server accepts that finished\n   0 session cache hits\n   0 session cache misses\n   0 session cache timeouts\n   0 callback cache hits\n   0 cache full overflows (128 allowed)\n---\nno client certificate available\n</BODY></HTML>\r\n\r\n' mac='\x97$\x1a\x18\x12B\r6,d\xb0\x9fMq\xdd\xe6\xd2\\\n\xe7' padding='\x08\x08\x08\x08\x08\x08\x08\x08' padding_len=0x8 |>>] |>
|   192.168.220.1   :54908 => 192.168.220.131 :443   | <SSL  records=[<TLSRecord  content_type=alert version=TLS_1_0 length=0x20 |<TLSAlert  level=249 description=101 |<Raw  load='2E\t\x87\xfb5\xa2aovC\xa9m\x19:\x9eR\xc4\xa0\x07N^v\xa83kh\xc0\xfd\xe9' |>>>] |>
|-> decrypted record                                 | <SSL  records=[<TLSRecord  content_type=alert version=TLS_1_0 length=0x20 |<TLSAlert  level=warning description=close_notify mac='\x8b\x9e,\x08az+0\x08N\xa0B\xc6\xfan\xfbZ\xf5\x82\x16' padding='\t\t\t\t\t\t\t\t\t' padding_len=0x9 |>>] |>

```

##### SSL Security Scanner

```python
# python examples/security_scanner.py localhost 443 

An example implementation of a passive TLS security scanner with custom starttls support:

    TLSScanner() generates TLS probe traffic  (optional)
    TLSInfo() passively evaluates the traffic and generates events/warning



Scanning with 10 parallel threads...
=> accepted_ciphersuites
=> compressions
=> heartbleed
=> poodle2
=> scsv
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
        server.heartbeat: None
>

[*] supported ciphers: 21/326
 * RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)
 * RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)
 * RSA_EXPORT_WITH_RC4_40_MD5 (0x0003)
 * RSA_WITH_RC4_128_MD5 (0x0004)
 * RSA_WITH_RC4_128_SHA (0x0005)
 * RSA_EXPORT_WITH_RC2_CBC_40_MD5 (0x0006)
 * RSA_EXPORT_WITH_DES40_CBC_SHA (0x0008)
 * RSA_WITH_DES_CBC_SHA (0x0009)
 * RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
 * RSA_WITH_AES_128_CBC_SHA (0x002f)
 * DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)
 * DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
 * DHE_RSA_EXPORT_WITH_DES40_CBC_SHA (0x0014)
 * DHE_RSA_WITH_DES_CBC_SHA (0x0015)
 * DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)
 * RSA_WITH_SEED_CBC_SHA (0x0096)
 * DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
 * DHE_RSA_WITH_SEED_CBC_SHA (0x009a)
 * DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)
 * DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)
 * RSA_WITH_AES_256_CBC_SHA (0x0035)

[*] supported protocol versions: 4/8
 * SSL_3_0 (0x0300)
 * TLS_1_0 (0x0301)
 * TLS_1_1 (0x0302)
 * TLS_1_2 (0x0303)

[*] supported compressions methods: 1/3
 * NULL (0x0000)

[*] Events: 8
* EVENT - HEARTBLEED - vulnerable
* EVENT - CIPHERS - Export ciphers enabled
* EVENT - CIPHERS - RC4 ciphers enabled
* EVENT - CIPHERS - MD5 ciphers enabled
* EVENT - FREAK - server supports RSA_EXPORT cipher suites
* EVENT - LOGJAM - server supports weak DH-Group (512) (DHE_*_EXPORT) cipher suites
* EVENT - PROTOCOL VERSION - SSLv3 supported
* EVENT - DOWNGRADE / POODLE - FALLBACK_SCSV - not honored

Scan took: 8.30570912361s
```

## Authors / Contributors
* tintinweb  ( http://oststrom.com  | https://github.com/tintinweb)
* alexmgr ( https://github.com/alexmgr )
