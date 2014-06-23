Scapy-SSL/TLS
=============

Support for parsing SSL/TLS in Scapy (http://www.secdev.org/projects/scapy/).


Installation
--------
1. deploy ssl_tls.py to ./scapy/layers
2. modify ./scapy/config.py to autoload this new layer
```diff
	config.py::Conf::load_layers 
	375,376c375
	<                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp",
	<                    "ssl_tls", ]
	---
	>                    "sebek", "skinny", "smb", "snmp", "tftp", "x509", "bluetooth", "dhcp6", "llmnr", "sctp", "vrrp"]
```
3. test
```python
	#> scapy
	   
	>>> TLSRecord
	<class 'scapy.layers.ssl_tls.TLSRecord'>
	   
```


## Output

```python
==============================================================================
>>> (TLSRecord()/TLSHeartBeat(data="1"*20)).show2()
###[ TLS Record ]###
  content_type= heartbeat
  version= TLS_1_0
  length= 23
###[ TLS Extension HeartBeat ]###
     type= unknown
     length= 20
     data= '11111111111111111111'
     padding= ''


```


## Authors
* tintinweb  ( http://oststrom.com  | http://github.com/tintinweb)
