Scapy-SSL/TLS
=============

Support for parsing/building SSL/TLS and DTLS in Scapy (http://www.secdev.org/projects/scapy/).

SSLv2,SSLv3(TLS),TLS,DTLS packet crafting, auto dissection, session tracking, key-sniffing and record decryption .

!! work in progress !!   
Please note that this code is highly experimental, you'll experience odd behavior so feel free to contribute:   
* bugfixes   
* new stuff   
* tests   


Features
---------
* TLS Session Tracking
 * Key sniffing for RSA key_exchange based ciphers (*RSA_WITH_*)
 * TLS Session sniffing
 * generic session decryption (*RSA_WITH_*) for sniffed/recorded traffic
* SSLv2 handshake
* SSL3/TLS records
* TLS handshakes, extensions, alerts
* DTLS records, handshakes


TODO
-----

* get rid of scapy/layers folder structure in sourcetree
* package for pip
* update/split documentation
* get rid of path magic in examples
* add support for TLSFinished
* add support for TLS1_1


Installation (optional)
--------

Note - it is *not* required to deploy files from the src/scapy/layers folder to your scapy_installation/layers directory in order to run the examples.

1) deploy all files in ./src/scapy/layers to ./scapy/layers

2) modify ./scapy/config.py to autoload this new layer
```diff
	config.py::Conf::load_layers 
	375,376c375
	<                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp",
	<                    "ssl_tls", ]
	---
	>                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp"]
 ```
3) try it
```python
#> scapy
	   
	>>> TLSRecord
	<class 'scapy.layers.ssl_tls.TLSRecord'>
	   
```


## Output

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

tls packet from example_client_hello_complex_invalid.py - contains invalid length fields and should raise TLSAlerts()
```python

>>> p.show()
###[ TLS Record ]###
  content_type= handshake
  version= TLS_1_2
  length= None
###[ TLS Handshake ]###
     type= client_hello
     length= None
###[ TLS Client Hello ]###
        version= TLS_1_0
        gmt_unix_time= 1403626178
        random_bytes= "\x7fX\xa0]\x90\x02!y\x8aj\xbb\xe8\xb02'\xd1\xba\xeb\xf5+\x9b\xd2\x1asl*\x8fZ"
        session_id_length= None
        session_id= ''
        cipher_suites_length= None
        cipher_suites= [0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254]
        compression_methods_length= None
        compression_methods= [0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254]
        extensions_length= None
        \extensions\
         |###[ TLS Extension ]###
         |  type= server_name
         |  length= None
         |###[ TLS Extension Servername Indication ]###
         |     length= None
         |     \server_names\
         |      |###[ TLS Servername ]###
         |      |  type= host
         |      |  length= 0x10
         |      |  data= 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
         |      |###[ TLS Servername ]###
         |      |  type= host
         |      |  length= 0xde
         |      |  data= ''
         |###[ TLS Extension ]###
         |  type= server_name
         |  length= None
         |###[ TLS Extension Servername Indication ]###
         |     length= None
         |     \server_names\
         |      |###[ TLS Servername ]###
         |      |  type= host
         |      |  length= 0x2
         |      |  data= ''

```

socket stream heartbleed example:
```python
import scapy
from scapy.layers.ssl_tls import *

import socket

target = ('target.local',443)

# create tcp socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(target)

p = TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')

s.sendall(p)
resp = s.recv(1024)
print "resp: %s"%repr(resp)
s.close()
```

socket stream valid client handshake allowing all ciphers/compressions.
```python
import scapy
from scapy.layers.ssl_tls import *

import socket


target = ('www.remote.host',443)            # MAKE SURE TO CHANGE THIS

# create tcp socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(target)

# create TLS Handhsake / Client Hello packet
p = TLSRecord()/TLSHandshake()/TLSClientHello(compression_methods=range(0xff), cipher_suites=range(0xff))
            
p.show()


print "sending TLS payload"
s.sendall(str(p))
resp = s.recv(1024)
print "received, %s"%repr(resp)

s.close()
```

manually dissect the response as SSL()
```python
>>> SSL(resp).show()
###[ SSL/TLS ]###
  \records\
   |###[ TLS Record ]###
   |  content_type= handshake
   |  version= TLS_1_0
   |  length= 0x4a
   |###[ TLS Handshake ]###
   |     type= server_hello
   |     length= 0x46
   |###[ TLS Server Hello ]###
   |        version= TLS_1_0
   |        gmt_unix_time= 1413462175
   |        random_bytes= '/\x91\x14O\xdd(/\x80<\xd5\xe4\xe4\x87Np\xdd\xb9-o\xd5\xf1d_\x96\x89\xad\x83\xcc'
   |        session_id_length= 0x20
   |        session_id= '\x89\xc7V\x0eyO9\xe4\xc0\x89\xfa\xe1,\xf2\xe4\xed?\xe5\xfd\xaa\xc4\x93\x00L\x9dG\x93 \xe8<H\x07'
   |        cipher_suite= RSA_WITH_RC4_128_MD5
   |        compression_method= DEFLATE
   |        extensions_length= None
   |        \extensions\
   |###[ TLS Record ]###
   |  content_type= handshake
   |  version= TLS_1_0
   |  length= 0x5d9
   |###[ TLS Handshake ]###
   |     type= certificate
   |     length= 0x5d5
   |###[ TLS Certificate List ]###
   |        length= 0x5d2
   |        \certificates\
   |         |###[ TLS Certificate ]###
   |         |  length= 0x5cf
   |         |  data= '0\x82\x05\xcb0\x82\x03\xb3\xa0\x03...'...

```


socket stream example to test remote implementations for protocol downgrading attemps (following latest SSL POODLE attacks) - example_ssl_tls_SCSV_fallback_test.py
```python
-----------------------
for: ('www.google.com', 443)
   record      hello   
('TLS_1_2', 'TLS_1_2')  ... TLSServerHello:            outer TLS_1_2 inner TLS_1_2
('TLS_1_2', 'TLS_1_1')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
('TLS_1_2', 'TLS_1_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
('TLS_1_2', 'SSL_3_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
('TLS_1_1', 'TLS_1_2')  ... TLSServerHello:            outer TLS_1_2 inner TLS_1_2
('TLS_1_1', 'TLS_1_1')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
('TLS_1_1', 'TLS_1_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
('TLS_1_1', 'SSL_3_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
('TLS_1_0', 'TLS_1_2')  ... TLSServerHello:            outer TLS_1_2 inner TLS_1_2
('TLS_1_0', 'TLS_1_1')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
('TLS_1_0', 'TLS_1_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
('TLS_1_0', 'SSL_3_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
('SSL_3_0', 'TLS_1_2')  ... TLSServerHello:            outer TLS_1_2 inner TLS_1_2
('SSL_3_0', 'TLS_1_1')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_1
('SSL_3_0', 'TLS_1_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_0
('SSL_3_0', 'SSL_3_0')  ... TLSAlert.INAPPROPRIATE_FALLBACK  SSL_3_0
overall:
    TLS_FALLBACK_SCSV_SUPPORTED   ...  True
    TLS_FALLBACK_SCSV_OK          ...  False
    SSLv3_ENABLED                 ...  True


```

socket stream SSLv2 dissection example
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

TLS1.0 Session Context tracking and RSA_WITH_AES_128_CBC_SHA key decryption by providing servers privkey
```python
* connecting ...
* init TLSSessionContext
* load servers privatekey for auto master-key decryption (RSA key only)
* -> client hello
sending TLS payload
timeout
* <- server hello
* chose premaster_secret and generate master_secret + key material
** chosen premaster_secret '\x03\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb'
** generated master_secret '\x9cR\xaa\xbb\xb6\x9c\x02^B`d\x1bf\x8au\x9f`\xa4\x99\xedm\x0b\xc8\xa9\t\xbd\xd2\xb5\x9fF\x97Y\xd0\xf4)\xef\xdc\x1e\xaaO\x94\xbaQ\xe7\ri\xed\xd4'
* fetch servers RSA pubkey
* encrypt premaster_secret with servers RSA pubkey
* -> TLSClientKeyExchange with EncryptedPremasterSecret
sending TLS payload
timeout
* -> ChangeCipherSpec
sending TLS payload
timeout
* FIXME: implement TLSFinished ...
* SSL Session parameter and keys: 
<TLSSessionCtx: id=52076240
	 src=('192.168.220.1', 59100)
	 dst=('192.168.220.131', 4433)
	 params.handshake.client=<TLSClientHello  version=TLS_1_0 gmt_unix_time=1420412557 random_bytes='RRRRRRRRRRRRRRRRRRRRRRRRRRRR' session_id_length=0x0 session_id='' cipher_suites_length=0x2 cipher_suites=[47] compression_methods_length=0x1 compression_methods=[0] extensions_length=0x0 |>
	 params.handshake.server=<TLSServerHello  version=TLS_1_0 gmt_unix_time=1420412561 random_bytes='\xc6\xe2)\xd6\xbc\x01j\x1a^\x18\xe6\rL\\E\x10Kl6G\xb2Y/\x99\xe1\x96b#' session_id_length=0x20 session_id='\xc3\x92\xe4l\xd7\xa9=\x11g\xc3\xc5z\t(\xfe2{\xb2\xa0`O\x84&\x9f0H\x13\xdf\x88]`x' cipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NULL |>
	 params.negotiated.ciphersuite=47
	 params.negotiated.key_exchange=['RSA']
	 params.negotiated.encryption=['AES', '128', 'CBC']
	 params.negotiated.mac=['SHA']
	 params.negotiated.compression=0
	 crypto.client.enc=<ssl_tls_crypto.PKCS7Wrapper object at 0x032506B0>
	 crypto.client.dec=<ssl_tls_crypto.PKCS7Wrapper object at 0x032506F0>
	 crypto.server.enc=<ssl_tls_crypto.PKCS7Wrapper object at 0x03250730>
	 crypto.server.dec=<ssl_tls_crypto.PKCS7Wrapper object at 0x03250770>
	 crypto.server.rsa.privkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x032368C8>
	 crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x03246D00>
	 crypto.session.encrypted_premaster_secret='K\x15N\xbb\xff\xf7\xf8\x86\xa6\x83\x0bH\x97\x0fCL\xe8\x0f\xf1^\xd9\xe9\xf7j\xea7\xb2\xf7B5\xaf\xe2\xd0\xf8\x88\x04`g\x19P\xec\x97\xf3\xbc\xea`\x98E\x98\xeaG\xd4\xa4\xacEQ8Z\xeaWl\x0e\xb9EZ\xe0\x14\x9a;Q\x04\x81@:\x12\x8f%{.\x00H\xad\x89\x86\xee\x85\xaa\xe9M\xf2S\xce\x87\xe9\\}A\x91O\xaa\x07"\x15\x95\x9d/,N\xee\xe6\xca\xc0T\xe8\xff`\xeb\x12\xaf`\xa6\xce\x99\xbf\xa0\xab \x06\x1f\x02\xdb|\xed(\xb9]\xf1\xdc\x93\xaa1\xea\x97\x87\x05\xc0Y\x94\xf4\x8fc\x1bDL\xc3$\xab\x05n\xe0\xe4\xacL\xa2\xa2CX\x1eI\x8c\\\x96\x86\x9a\xaf\x9b\xd8\xbe#\xd3\xd3m\x02\xfe\xa7l\xb1*n\x88Q\xa0\x84\xf3\xbf\xf8z\xd4\xf3\x9fg\xeeZ?\x1c\xf5j8\xa0\xe2\x06\xbd\xb8\x1e\x1c\x8f]\xca\xe6\x0f\xf9\xba,\x82\x82v,?\x83oCg\xa9\xc4H\xdd)i\xbdO\n\xfc\x1e\xca\x8f\x90S<C\xe0\xb8\xb0\x0f\xd1\x06\xf6'
	 crypto.session.premaster_secret='\x03\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb'
	 crypto.session.master_secret='\x9cR\xaa\xbb\xb6\x9c\x02^B`d\x1bf\x8au\x9f`\xa4\x99\xedm\x0b\xc8\xa9\t\xbd\xd2\xb5\x9fF\x97Y\xd0\xf4)\xef\xdc\x1e\xaaO\x94\xbaQ\xe7\ri\xed\xd4'
	 crypto.session.randombytes.client='T\xa9\xc6\x8dRRRRRRRRRRRRRRRRRRRRRRRRRRRR'
	 crypto.session.randombytes.server='T\xa9\xc6\x91\xc6\xe2)\xd6\xbc\x01j\x1a^\x18\xe6\rL\\E\x10Kl6G\xb2Y/\x99\xe1\x96b#'
	 crypto.session.key.client.mac='?P\x1c\xc87\x9b\xd0\x81\xfc\xe9\x80\xda\xc6\x85\x10\xdb\xe4\x15\xd65'
	 crypto.session.key.client.encryption='"\x07\xfe\xce\x00Gxz\xa3\x0e*\xd5\xfco\xc2\x01'
	 crypto.session.key.cllient.iv='\x1b\xfc\x01c8fv\xdc1t\xef\xd4$\xe8\xf4\xd9'
	 crypto.session.key.server.mac='I\x8f\xf3\xe39H\x89\xed\xaep\xd8\x01\xc9\x99]bL^\x0b6'
	 crypto.session.key.server.encryption='l|1C`u\x81\xea.&\xd4t\xef\x1b\xb3\xd3'
	 crypto.session.key.server.iv='V\x02\xc3sF\x9bWZ\x86"\x9e\x99\x1b\x04\x9b\xeb'
	 crypto.session.key.length.mac=20
	 crypto.session.key.length.encryption=16
	 crypto.session.key.length.iv=16
>
* you should now be able to encrypt/decrypt any client/server communication for this session :)

```

TLS1.0 auto-decrypting sniffer for RSA_WITH_AES_128_CBC_SHA and known privkey: (client traffic decryption)
```python
* Server: #> openssl s_server -accept 443 -debug -cipher AES128-SHA
# /src/openssl/apps/openssl s_server -accept 443 -debug -cipher AES128-SHA
Using default temp DH parameters
ACCEPT

* Sniffer: python example_sessionctx-sniffer.py
** optionally set conf.iface to the listening device
** wait for sniffer to start up
* Client: #> openssl s_client -connect 192.168.220.131:443 -tls1

CONNECTED(00000003)
depth=0 C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = Test Se
ver Cert
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = Test Se
ver Cert
verify error:num=27:certificate not trusted
verify return:1
depth=0 C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = Test Se
ver Cert
verify error:num=21:unable to verify the first certificate
verify return:1
---
Certificate chain
 0 s:/C=UK/O=OpenSSL Group/OU=FOR TESTING PURPOSES ONLY/CN=Test Server Cert
   i:/C=UK/O=OpenSSL Group/OU=FOR TESTING PURPOSES ONLY/CN=OpenSSL Test Interme
iate CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MIID5zCCAs+gAwIBAgIJALnu1NlVpZ6zMA0GCSqGSIb3DQEBBQUAMHAxCzAJBgNV
BAYTAlVLMRYwFAYDVQQKDA1PcGVuU1NMIEdyb3VwMSIwIAYDVQQLDBlGT1IgVEVT
VElORyBQVVJQT1NFUyBPTkxZMSUwIwYDVQQDDBxPcGVuU1NMIFRlc3QgSW50ZXJt
ZWRpYXRlIENBMB4XDTExMTIwODE0MDE0OFoXDTIxMTAxNjE0MDE0OFowZDELMAkG
A1UEBhMCVUsxFjAUBgNVBAoMDU9wZW5TU0wgR3JvdXAxIjAgBgNVBAsMGUZPUiBU
RVNUSU5HIFBVUlBPU0VTIE9OTFkxGTAXBgNVBAMMEFRlc3QgU2VydmVyIENlcnQw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzhPOSNtyyRspmeuUpxfNJ
KCLTuf7g3uQ4zu4iHOmRO5TQci+HhVlLZrHF9XqFXcIP0y4pWDbMSGuiorUmzmfi
R7bfSdI/+qIQt8KXRH6HNG1t8ou0VSvWId5TS5Dq/er5ODUr9OaaDva7EquHIcMv
vPQGuI+OEAcnleVCy9HVEIySrO4P3CNIicnGkwwiAud05yUAq/gPXBC1hTtmlPD7
TVcGVSEiJdvzqqlgv02qedGrkki6GY4S7GjZxrrf7Foc2EP+51LJzwLQx3/JfrCU
41NEWAsu/Sl0tQabXESN+zJ1pDqoZ3uHMgpQjeGiE0olr+YcsSW/tJmiU9OiAr8R
AgMBAAGjgY8wgYwwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBeAwLAYJYIZI
AYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQW
BBSCvM8AABPR9zklmifnr9LvIBturDAfBgNVHSMEGDAWgBQ2w2yI55X+sL3szj49
hqshgYfa2jANBgkqhkiG9w0BAQUFAAOCAQEAqb1NV0B0/pbpK9Z4/bNjzPQLTRLK
WnSNm/Jh5v0GEUOE/Beg7GNjNrmeNmqxAlpqWz9qoeoFZax+QBpIZYjROU3TS3fp
yLsrnlr0CDQ5R7kCCDGa8dkXxemmpZZLbUCpW2Uoy8sAA4JjN9OtsZY7dvUXFgJ7
vVNTRnI01ghknbtD+2SxSQd3CWF6QhcRMAzZJ1z1cbbwGDDzfvGFPzJ+Sq+zEPds
xoVLLSetCiBc+40ZcDS5dV98h9XD7JMTQfxzA7mNGv73JoZJA6nFgj+ADSlJsY/t
JBv+z1iQRueoh9Qeee+ZbRifPouCB8FDx+AltvHTANdAq0t/K3o+pplMVA==
-----END CERTIFICATE-----
subject=/C=UK/O=OpenSSL Group/OU=FOR TESTING PURPOSES ONLY/CN=Test Server Cert
issuer=/C=UK/O=OpenSSL Group/OU=FOR TESTING PURPOSES ONLY/CN=OpenSSL Test Inter
ediate CA
---
No client certificate CA names sent
---
SSL handshake has read 1324 bytes and written 540 bytes
---
New, TLSv1/SSLv3, Cipher is AES128-SHA
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
SSL-Session:
    Protocol  : TLSv1
    Cipher    : AES128-SHA
    Session-ID: AD7942ED178AEAE42D340ADD964E7281818B12C97B313E90F6076D4A42197A8

    Session-ID-ctx:
    Master-Key: 32C0F3540AD6487A9B5335AEE93FA369184D6C07A42AF5DE33BFF956FFA8DB2
0E50EAF3F406537FC58BD098EF25E7C7
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 11 29 15 8f 6d 49 df f5-a8 2b fe d5 95 bf a7 64   .)..mI...+.....d
    0010 - 25 31 27 87 dd 4c 11 43-ca 91 f4 3c 2d 27 79 1a   %1'..L.C...<-'y.
    0020 - c1 8e 5d 14 2f 3d 25 84-d1 9d cd e3 f8 d7 6e ad   ..]./=%.......n.
    0030 - 04 cb e1 b6 6c e1 1d 96-05 0e 5c 6c 56 0b 8c c8   ....l.....\lV...
    0040 - 53 5b 0c 0b 94 f7 05 2e-54 93 e6 e7 0c d6 5e 9c   S[......T.....^.
    0050 - 2a 01 1a e6 fe d5 44 87-8b aa 5f df 04 86 f2 e2   *.....D..._.....
    0060 - 2a d0 0e 6a 16 c9 34 db-4a 11 5e ec 54 bf 4c 58   *..j..4.J.^.T.LX
    0070 - 45 b8 58 c3 00 d6 57 52-ff 71 24 19 4c 41 44 1a   E.X...WR.q$.LAD.
    0080 - 94 b1 ce bc 4f 84 e9 1d-f4 f1 ef 7e 82 23 8c c2   ....O......~.#..
    0090 - 4a 0f 81 50 04 28 e7 76-d7 14 10 43 98 0a b9 06   J..P.(.v...C....

    Start Time: 1420428003
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
---
THIS CONTENT IS ENCRYPTED! :)


* Sniffer:

WARNING: No route found for IPv6 destination :: (no default route?)
* load servers privatekey for auto master-key decryption (RSA key only)
processing.. <TLSRecord  content_type=handshake version=TLS_1_0 length=0xd1 |<TLSHandshake  type=client_hello length=0xcd |<TLSClientHello  version=TLS_1_0 gmt_unix_time=3877396011L random_bytes='\x04\xf7m\x141\xa3\xf7\n\x01o\x17\xb9wc\xa7\xe8!Z\xc7A\xb9\xa7X\xf1\x02\xc9\xa8*' session_id_length=0x0 session_id='' cipher_suites_length=0x5a cipher_suites=[49172, 49162, 57, 56, 136, 135, 49167, 49157, 53, 132, 49171, 49161, 51, 50, 154, 153, 69, 68, 49166, 49156, 47, 150, 65, 49169, 49159, 49164, 49154, 5, 4, 49170, 49160, 22, 19, 49165, 49155, 10, 21, 18, 9, 20, 17, 8, 6, 3, 255] compression_methods_length=0x2 compression_methods=[1, 0] extensions_length=0x49 extensions=[<TLSExtension  type=ec_point_formats length=0x4 |<TLSExtECPointsFormat  length=0x3 ec_point_formats=[0, 1, 2] |>>, <TLSExtension  type=elliptic_curves length=0x34 |<TLSExtEllipticCurves  length=0x32 elliptic_curves=[14, 13, 25, 11, 12, 24, 9, 10, 22, 23, 8, 6, 7, 20, 21, 4, 5, 18, 19, 1, 2, 3, 15, 16, 17] |>>, <TLSExtension  type=session_ticket_tls length=0x0 |>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode='\x01' |>>] |>>>
processing.. <TLSRecord  content_type=handshake version=TLS_1_0 length=0x3a |<TLSHandshake  type=server_hello length=0x36 |<TLSServerHello  version=TLS_1_0 gmt_unix_time=3377250372L random_bytes='?|\x08`\x07|o\xed\xe0\xd6/\xea8\xd9\x11\x93\xba\x94\xd6\xf6o\x9b\x10\xe0B\x1b\xa4\xd0' session_id_length=0x0 session_id='' cipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NULL extensions_length=0xe extensions=[<TLSExtension  type=renegotiationg_info length=0x1 |<Raw  load='\x00' |>>, <TLSExtension  type=session_ticket_tls length=0x0 |>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode='\x01' |>>] |>>>
processing.. <TLSRecord  content_type=handshake version=TLS_1_0 length=0x3f5 |<TLSHandshake  type=certificate length=0x3f1 |<TLSCertificateList  length=0x3ee certificates=[<TLSCertificate  length=0x3eb data='0\x82\x03\xe70\x82\x02\xcf\xa0\x03\x02\x01\x02\x02\t\x00\xb9\xee\xd4\xd9U\xa5\x9e\xb30\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000p1\x0b0\t\x06\x03U\x04\x06\x13\x02UK1\x160\x14\x06\x03U\x04\n\x0c\rOpenSSL Group1"0 \x06\x03U\x04\x0b\x0c\x19FOR TESTING PURPOSES ONLY1%0#\x06\x03U\x04\x03\x0c\x1cOpenSSL Test Intermediate CA0\x1e\x17\r111208140148Z\x17\r211016140148Z0d1\x0b0\t\x06\x03U\x04\x06\x13\x02UK1\x160\x14\x06\x03U\x04\n\x0c\rOpenSSL Group1"0 \x06\x03U\x04\x0b\x0c\x19FOR TESTING PURPOSES ONLY1\x190\x17\x06\x03U\x04\x03\x0c\x10Test Server Cert0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xf3\x84\xf3\x926\xdc\xb2F\xcafz\xe5)\xc5\xf3I("\xd3\xb9\xfe\xe0\xde\xe48\xce\xee"\x1c\xe9\x91;\x94\xd0r/\x87\x85YKf\xb1\xc5\xf5z\x85]\xc2\x0f\xd3.)X6\xccHk\xa2\xa2\xb5&\xceg\xe2G\xb6\xdfI\xd2?\xfa\xa2\x10\xb7\xc2\x97D~\x874mm\xf2\x8b\xb4U+\xd6!\xdeSK\x90\xea\xfd\xea\xf985+\xf4\xe6\x9a\x0e\xf6\xbb\x12\xab\x87!\xc3/\xbc\xf4\x06\xb8\x8f\x8e\x10\x07\'\x95\xe5B\xcb\xd1\xd5\x10\x8c\x92\xac\xee\x0f\xdc#H\x89\xc9\xc6\x93\x0c"\x02\xe7t\xe7%\x00\xab\xf8\x0f\\\x10\xb5\x85;f\x94\xf0\xfbMW\x06U!"%\xdb\xf3\xaa\xa9`\xbfM\xaay\xd1\xab\x92H\xba\x19\x8e\x12\xech\xd9\xc6\xba\xdf\xecZ\x1c\xd8C\xfe\xe7R\xc9\xcf\x02\xd0\xc7\x7f\xc9~\xb0\x94\xe3SDX\x0b.\xfd)t\xb5\x06\x9b\\D\x8d\xfb2u\xa4:\xa8g{\x872\nP\x8d\xe1\xa2\x13J%\xaf\xe6\x1c\xb1%\xbf\xb4\x99\xa2S\xd3\xa2\x02\xbf\x11\x02\x03\x01\x00\x01\xa3\x81\x8f0\x81\x8c0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xe00,\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x1f\x16\x1dOpenSSL Generated Certificate0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x82\xbc\xcf\x00\x00\x13\xd1\xf79%\x9a\'\xe7\xaf\xd2\xef \x1bn\xac0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x146\xc3l\x88\xe7\x95\xfe\xb0\xbd\xec\xce>=\x86\xab!\x81\x87\xda\xda0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\xa9\xbdMW@t\xfe\x96\xe9+\xd6x\xfd\xb3c\xcc\xf4\x0bM\x12\xcaZt\x8d\x9b\xf2a\xe6\xfd\x06\x11C\x84\xfc\x17\xa0\xeccc6\xb9\x9e6j\xb1\x02Zj[?j\xa1\xea\x05e\xac~@\x1aHe\x88\xd19M\xd3Kw\xe9\xc8\xbb+\x9eZ\xf4\x0849G\xb9\x02\x081\x9a\xf1\xd9\x17\xc5\xe9\xa6\xa5\x96Km@\xa9[e(\xcb\xcb\x00\x03\x82c7\xd3\xad\xb1\x96;v\xf5\x17\x16\x02{\xbdSSFr4\xd6\x08d\x9d\xbbC\xfbd\xb1I\x07w\tazB\x17\x110\x0c\xd9\'\\\xf5q\xb6\xf0\x180\xf3~\xf1\x85?2~J\xaf\xb3\x10\xf7l\xc6\x85K-\'\xad\n \\\xfb\x8d\x19p4\xb9u_|\x87\xd5\xc3\xec\x93\x13A\xfcs\x03\xb9\x8d\x1a\xfe\xf7&\x86I\x03\xa9\xc5\x82?\x80\r)I\xb1\x8f\xed$\x1b\xfe\xcfX\x90F\xe7\xa8\x87\xd4\x1ey\xef\x99m\x18\x9f>\x8b\x82\x07\xc1C\xc7\xe0%\xb6\xf1\xd3\x00\xd7@\xabK\x7f+z>\xa6\x99LT' |>] |>>>
processing.. <TLSRecord  content_type=handshake version=TLS_1_0 length=0x4 |<TLSHandshake  type=server_hello_done length=0x0 |>>
processing.. <TLSRecord  content_type=handshake version=TLS_1_0 length=0x106 |<TLSHandshake  type=client_key_exchange length=0x102 |<TLSClientKeyExchange  length=0x100 |<Raw  load="\\\xa5\xed\x95\xa00\xb3\xc32\xdb\xf4\x88\xf2\xec\x0f\xedF6\x98\x0b\xd1\xd8<}\xb1@\x85\x94s\x12,\xb7l\xfeJ\xa4\x99\xf9\x16\x1c?_)\x86M;\x06BR\xa6\x01\xbbC\xb9\xca\xb3\xd7\n\x1f\xb9H\xbdQD\xad\x1b\xecG\xd2T\x94-\x85\x8da \xca(\xdb\xbc\x91[_\xffE0\xc0\xc9W\x8c\xce\xfey\xfe\x8c\x11\x13W+\xb4\xe6~\xd9d74\xfa7\xbbkI\x0eyt\x89m\xf6-\xa5]\xe3d\xb3\xed]\x1d5T2\xaf{\xa4\x03i\xfd\xdb9\x85:\xac\x11\xe1\x94JgI{\xd2\xc9@g8\xb2\xb9\x9e\x07Z\x0b.]\xb1\x0e\xb6\xdd\xb8C\x81\xce\xb7\x19q\xd2\x94)\x14IPX\xcd\xf6{^\xbb\xe6r\xae~1dkZ\x1c\xd0\xdb\xaddA\xc1\xe4\x95\x8b4\xa4\x94Gf\xba\xfe\xacy\x0e\xb8\xa5\x9fb\x86\x02\x95r\xed\x02\x08\xa3\x83\x0e\xbd\x91\xc5c*\xc4\x90\x05\x9f'm\xcd\xec\xc3Xd\x88\x7f\xf8CL\xd1\xd2%1\xe4NL\xb3C\x1c" |>>>>
<TLSSessionCtx: id=51854928
	 params.handshake.client=<TLSClientHello  version=TLS_1_0 gmt_unix_time=3877396011L random_bytes='\x04\xf7m\x141\xa3\xf7\n\x01o\x17\xb9wc\xa7\xe8!Z\xc7A\xb9\xa7X\xf1\x02\xc9\xa8*' session_id_length=0x0 session_id='' cipher_suites_length=0x5a cipher_suites=[49172, 49162, 57, 56, 136, 135, 49167, 49157, 53, 132, 49171, 49161, 51, 50, 154, 153, 69, 68, 49166, 49156, 47, 150, 65, 49169, 49159, 49164, 49154, 5, 4, 49170, 49160, 22, 19, 49165, 49155, 10, 21, 18, 9, 20, 17, 8, 6, 3, 255] compression_methods_length=0x2 compression_methods=[1, 0] extensions_length=0x49 extensions=[<TLSExtension  type=ec_point_formats length=0x4 |<TLSExtECPointsFormat  length=0x3 ec_point_formats=[0, 1, 2] |>>, <TLSExtension  type=elliptic_curves length=0x34 |<TLSExtEllipticCurves  length=0x32 elliptic_curves=[14, 13, 25, 11, 12, 24, 9, 10, 22, 23, 8, 6, 7, 20, 21, 4, 5, 18, 19, 1, 2, 3, 15, 16, 17] |>>, <TLSExtension  type=session_ticket_tls length=0x0 |>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode='\x01' |>>] |>
	 params.handshake.server=<TLSServerHello  version=TLS_1_0 gmt_unix_time=3377250372L random_bytes='?|\x08`\x07|o\xed\xe0\xd6/\xea8\xd9\x11\x93\xba\x94\xd6\xf6o\x9b\x10\xe0B\x1b\xa4\xd0' session_id_length=0x0 session_id='' cipher_suite=RSA_WITH_AES_128_CBC_SHA compression_method=NULL extensions_length=0xe extensions=[<TLSExtension  type=renegotiationg_info length=0x1 |<Raw  load='\x00' |>>, <TLSExtension  type=session_ticket_tls length=0x0 |>, <TLSExtension  type=heartbeat length=0x1 |<TLSExtHeartbeat  mode='\x01' |>>] |>
	 params.negotiated.ciphersuite=47
	 params.negotiated.key_exchange=['RSA']
	 params.negotiated.encryption=['AES', '128', 'CBC']
	 params.negotiated.mac=['SHA']
	 params.negotiated.compression=0
	 crypto.client.enc=<ssl_tls_crypto.PKCS7Wrapper object at 0x031E98F0>
	 crypto.client.dec=<ssl_tls_crypto.PKCS7Wrapper object at 0x031E9850>
	 crypto.server.enc=<ssl_tls_crypto.PKCS7Wrapper object at 0x031E9710>
	 crypto.server.dec=<ssl_tls_crypto.PKCS7Wrapper object at 0x031E9690>
	 crypto.server.rsa.privkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x031E74B8>
	 crypto.server.rsa.pubkey=<Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher instance at 0x031FD058>
	 crypto.session.encrypted_premaster_secret="\\\xa5\xed\x95\xa00\xb3\xc32\xdb\xf4\x88\xf2\xec\x0f\xedF6\x98\x0b\xd1\xd8<}\xb1@\x85\x94s\x12,\xb7l\xfeJ\xa4\x99\xf9\x16\x1c?_)\x86M;\x06BR\xa6\x01\xbbC\xb9\xca\xb3\xd7\n\x1f\xb9H\xbdQD\xad\x1b\xecG\xd2T\x94-\x85\x8da \xca(\xdb\xbc\x91[_\xffE0\xc0\xc9W\x8c\xce\xfey\xfe\x8c\x11\x13W+\xb4\xe6~\xd9d74\xfa7\xbbkI\x0eyt\x89m\xf6-\xa5]\xe3d\xb3\xed]\x1d5T2\xaf{\xa4\x03i\xfd\xdb9\x85:\xac\x11\xe1\x94JgI{\xd2\xc9@g8\xb2\xb9\x9e\x07Z\x0b.]\xb1\x0e\xb6\xdd\xb8C\x81\xce\xb7\x19q\xd2\x94)\x14IPX\xcd\xf6{^\xbb\xe6r\xae~1dkZ\x1c\xd0\xdb\xaddA\xc1\xe4\x95\x8b4\xa4\x94Gf\xba\xfe\xacy\x0e\xb8\xa5\x9fb\x86\x02\x95r\xed\x02\x08\xa3\x83\x0e\xbd\x91\xc5c*\xc4\x90\x05\x9f'm\xcd\xec\xc3Xd\x88\x7f\xf8CL\xd1\xd2%1\xe4NL\xb3C\x1c"
	 crypto.session.premaster_secret="\x03\x01\x93\x1b\x87o;Y\r\x88\xc3\x93.\x14\x8b'\n\\\x08\xf6\x1a\xd1M\x1f\xe9\x99\x18\xe9\x07\xe3\x1a\x86\x9e%;c\xa1\\3@O\xd1\x04\xa3\xbf\x11N\xcd"
	 crypto.session.master_secret='2\xc0\xf3T\n\xd6Hz\x9bS5\xae\xe9?\xa3i\x18Ml\x07\xa4*\xf5\xde3\xbf\xf9V\xff\xa8\xdb/\x0eP\xea\xf3\xf4\x06S\x7f\xc5\x8b\xd0\x98\xef%\xe7\xc7'
	 crypto.session.randombytes.client='\xe7\x1c^+\x04\xf7m\x141\xa3\xf7\n\x01o\x17\xb9wc\xa7\xe8!Z\xc7A\xb9\xa7X\xf1\x02\xc9\xa8*'
	 crypto.session.randombytes.server='\xc9L\xc0D?|\x08`\x07|o\xed\xe0\xd6/\xea8\xd9\x11\x93\xba\x94\xd6\xf6o\x9b\x10\xe0B\x1b\xa4\xd0'
	 crypto.session.key.client.mac='\xf2\x98\xe1vpX\x7f\xf1K\xef+\xfc\xaf\xad\xe7\xfe\xa5\xb8G\x0b'
	 crypto.session.key.client.encryption='F\x1b\xbe.\xe0\xa6\xc7I\x7fj\xb6\xdf&0\x1e\xa0'
	 crypto.session.key.cllient.iv='\xb4F\xe8\xe9\xa5\xb1\x95\xce/\x1bF\xd0\xb5\x97>\xad'
	 crypto.session.key.server.mac='\x83\x1c\xac=\x969\xca\xbb\x8c\x98O\xe5Ep\x87\x10\x98\xb6g\xb9'
	 crypto.session.key.server.encryption='\x1e$\x89\x11]j\xb6\x88V\x1f\xd6\xe1\xc1W\xdd\x0b'
	 crypto.session.key.server.iv='\x14\xca3\xcb\x11\xf2\xb5P\xf9\x81\xca\x92\xea\xcb\xc2\xab'
	 crypto.session.key.length.mac=20
	 crypto.session.key.length.encryption=16
	 crypto.session.key.length.iv=16
>
processing.. <TLSRecord  content_type=change_cipher_spec version=TLS_1_0 length=0x1 |<TLSChangeCipherSpec  message='\x01' |>>
processing.. <TLSRecord  content_type=handshake version=TLS_1_0 length=0x30 |<TLSHandshake  type=30 length=0xc4323d |<Raw  load='\xcf\x88\x9e\xfb8\xe6:R\xdc\x9c\x0c\x17c\x05\xf1\xc6E\xc1U?\xc6\xb6\xf0\xcd\xd3\xb2Yb\xc8\x14\xe7\x95"G\x90\n\x91\xff\xb2\x1b\x08\x1cH/' |>>>
processing.. <TLSRecord  content_type=application_data version=TLS_1_0 length=0x20 |<Raw  load='sf\xf64\xdc\xe1Z\xecH(nJ\xb6SE\xe4\xa7\xe3J2\x7f\x93I\xcf\xccH\x0ee\xc3:\x7f\xff' |>>
###[ TLS Record ]###
  content_type= application_data
  version   = TLS_1_0
  length    = 0x20
###[ TLS Ciphertext Decrypted ]###
     data      = None
###[ TLS Ciphertext MAC ]###
        mac       = '\xfc\x8f\x83\x07VB@s\xe5\x81-\x10*[>\xb8\x90\x01\xa7\xba\x0b'
processing.. <TLSRecord  content_type=application_data version=TLS_1_0 length=0x40 |<Raw  load='\xa5\x9c\xd2\x8c\xbc\x9b\x02|\xcb\xd0A\xf7\xb6\x03\xc5r(\x8f\x9f\xd5x\x94\x02A\xa5\xfe]\x08\xf5/\xe7Nz\x14\xea\x8a\xdf8\xc2\xab&q=XO\xca\x89\\\xe3\x15!V^x\x85\xe9\xa2\xff\xc8\xb0\xb5\xc8\xf2\x9e' |>>
###[ TLS Record ]###
  content_type= application_data
  version   = TLS_1_0
  length    = 0x40
###[ TLS Ciphertext Decrypted ]###
     data      = 'THIS CONTENT IS ENCRYPTED! :)\n'
###[ TLS Ciphertext MAC ]###
        mac       = '\xfar \x13V\xf38\xe9\xf6\x9eo\x8c\xb9\xe0p\x16\xc5D0\xc5\r'

```
TLSCiphertextDecrypted 


## Authors
* tintinweb  ( http://oststrom.com  | http://github.com/tintinweb)
