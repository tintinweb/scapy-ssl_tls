#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
import sys
sys.path.append("../scapy/layers")
import ssl_tls_crypto 
from Crypto.PublicKey import RSA

if __name__=="__main__":
    pemkey = """-----BEGIN CERTIFICATE-----
    MIIEezCCA2OgAwIBAgIIKKmyteXCe+wwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
    BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
    cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQxMDIyMTMxNjM3WhcNMTUwMTIwMDAwMDAw
    WjBlMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
    TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEUMBIGA1UEAwwLKi5n
    b29nbGUuYXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTV4n1WU/e
    ZnEUhZ4gRkhLCFHKRNQ+/93sOzAgNHY5hyK+HK8jETP2d6hdCjw+j5cBPrmfeNPY
    rQ/7LV5PA9JzJXNBJ//9vKSo7EaJcDsdXziZtWKqkQIbzCbgW8olufHYxCDSISMa
    kQxDLWWBXxGWbVOtYe1LeLijCSKE2nFfdDUUrFlXvc2idl5AOI/DS5ZVY5ddCQrl
    O4c5vgxvdu7sU9qIRrr7hyge/KKMw9cCTETAtknrL0kLIgYBtsKX24nJANKyazt9
    uVbbMDmroFX99UDamSyaGHt7OBBfgamJakyAVu30e/5f1HR6njnzaoftLxIp3PeU
    9ebEIaOQxzdzAgMBAAGjggFJMIIBRTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
    BQUHAwIwIQYDVR0RBBowGIILKi5nb29nbGUuYXSCCWdvb2dsZS5hdDBoBggrBgEF
    BQcBAQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFH
    Mi5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29j
    c3AwHQYDVR0OBBYEFANwSKccemQhfqivoa25syO2IkqbMAwGA1UdEwEB/wQCMAAw
    HwYDVR0jBBgwFoAUSt0GFhu89mi1dvWBtrtiGrpagS8wFwYDVR0gBBAwDjAMBgor
    BgEEAdZ5AgUBMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNv
    bS9HSUFHMi5jcmwwDQYJKoZIhvcNAQEFBQADggEBABKhwsnXBSJSFKos943jBeXC
    oDz/MxDrORwu7VDipoYZal6RCWYyKOflz0kXE4hoJcNtW8d3sXy1fWyyXE1pDw+x
    TvW15HqYNjn72TzuppfDMYhcjXzH4wZ+Y+tzm6zd8fA9CyKNZai6+PEI8YcP+yCe
    2w047IsQdsjqBkWYegbeFRcOFAh5M5ITdjXgC8dACzZx87bWvCpvT1g6dGQq1N1p
    pdFaJ57ZB1SRm3il7AMLbO1mFSuA/RcK3DYzlkQEJMD6RZGB/ufR7WUep3m7Lfk1
    +v0yMaqeG8gChVsM+bdsTeTw5Uy4hHEdnC2Kip39A+v6+UyU3tzHcM+z3Xxo/H0=
    -----END CERTIFICATE-----
    """
    
    k= ssl_tls_crypto.x509_extract_pubkey_from_pem(pemkey)
    if not k.can_encrypt():
        raise Exception("Failed")
    
    print k.can_sign()
    if not k.publickey():
        raise Exception("Failed")
    
    test = "a"*10000
    enc= k.encrypt(test,None)
    print len(enc[0]),enc

    if len(''.join(enc)):
        print "SUCCESS!"
    else:
        raise Exception("Failed")
        
    exit()