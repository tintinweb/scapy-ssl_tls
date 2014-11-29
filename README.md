Scapy-SSL/TLS
=============

Support for parsing/building SSL/TLS and DTLS in Scapy (http://www.secdev.org/projects/scapy/).

SSLv2,SSLv3(TLS),TLS,DTLS packet crafting and auto dissection.



!! work in progress !!   
Please note that this code is highly experimental, you'll experience odd behavior so feel free to contribute:   
* bugfixes   
* new stuff   
* tests   


Features
---------
* SSLv2 handshake
* TLS/SSL3 records
* TLS handshake
* DTLS records and handshake

Installation
--------
1) copy all files inside src/scapy/layers to ./scapy/layers

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


## Authors
* tintinweb  ( http://oststrom.com  | http://github.com/tintinweb)
