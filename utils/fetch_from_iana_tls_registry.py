#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
'''
Create python dictionary from IANA only TLS registry

aye, dirty hacks approaching.
'''
import urllib2
import struct
import xml.etree.ElementTree as ET
import datetime
import sys

URL_TLSPARAMETERS = "https://www.iana.org/assignments/tls-parameters/tls-parameters.xml"

def pprint(name,d):
    print "%s = {"%name
    for k in sorted(d):
        print "    0x%0.4x: '%s',"%(k,d[k])
    print "    }"

def registry_to_dict(url,id):
    print "# cipher_list generated from %s"%url
    print "# from id: %s"%id
    print "# date: %s"%datetime.date.today()
    d = {}
    data = urllib2.urlopen(url).read()
    t = ET.fromstring(data)
    for cipher in t.findall("{http://www.iana.org/assignments}registry[@id='%s']/{http://www.iana.org/assignments}record"%id):
        value = cipher.find("./{http://www.iana.org/assignments}value").text
        name = cipher.find("./{http://www.iana.org/assignments}description").text
        try:
            if "," in value:
                raw_vals = [int(v,16) for v in value.strip().split(",")]
                value = struct.pack("!BB",*raw_vals)
                value = struct.unpack("!H",value)[0]
            else:
                value = int(value,16)
            d[value]=name.lstrip("TLS_")
        except ValueError, e:
            print "# skipping: %s"%repr(e)
    return d

def main(id='tls-parameters-4'):
    d = registry_to_dict(URL_TLSPARAMETERS, id)
    pprint('data',d)

if __name__=="__main__":
    id = sys.argv[1] if len(sys.argv)>1 else "tls-parameters-4" 
    main(id)