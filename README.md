Scapy-SSL/TLS
=============

Support for parsing SSL/TLS in Scapy (http://www.secdev.org/projects/scapy/).


Installation
--------
1. deploy ssl_tls.py to ./scapy/layers
2. modify ./scapy/config.py to autoload this new layer

	config.py::Conf::load_layers 
	375,376c375
	<                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp",
	<                    "ssl_tls", ]
	---
	>                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp"]

3. test
	#> scapy
	   
	>>> TLSRecord
	<class 'scapy.layers.ssl_tls.TLSRecord'>
	   

Example
--------


## Output

```python
==============================================================================
>>> (IP(dst="192.168.201.10")/TCP(dport=443)/TLSRecord()/TLSHeartBeat(data="1"*20)).show2()
###[ IP ]###
  version= 4L
  ihl= 5L
  tos= 0x0
  len= 68
  id= 1
  flags=
  frag= 0L
  ttl= 64
  proto= tcp
  chksum= 0x678e
  src= 192.168.200.201
  dst= 192.168.201.10
  \options\
###[ TCP ]###
     sport= ftp_data
     dport= https
     seq= 0
     ack= 0
     dataofs= 5L
     reserved= 0L
     flags= S
     window= 8192
     chksum= 0x5ece
     urgptr= 0
     options= []
###[ HTTP ]###
###[ Raw ]###
           load= '\x18\x03\x01\x00\x17\x01\x00\x1411111111111111111111'

```

## Authors
* tintinweb  ( http://oststrom.com  | http://github.com/tintinweb)
