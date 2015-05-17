#! -*- coding: utf-8 -*-

import unittest
import ssl_tls as tls
import ssl_tls_crypto as tlsc

from scapy.layers import x509

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

class TestToRaw(unittest.TestCase):

    def setUp(self):
        self.pem_priv_key = """-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDDLrmt4lKRpm6P
2blptwJsa1EBuxuuAayLjwNqKGvm5c1CAUEa/NtEpUMM8WYKRDwxzakUIGI/BdP3
NOEMphcs5+OekgJLhzoSdtAIrXPy8JIidENZE6FzCJ2b6fHU5O4hoNvv1Bx5yoZr
HVaWJIZMRRocJJ0Nf9oMaU8IE6m6OdBzQHEwcnL2/a8Q3VxstHufzjILmaZD9WL+
6AESlQMKZPNQ+Xd7d4nvnVkY4ZV46tA+KvADGuotgovQwG+uiyQoGRrQUms21vHF
zIvd3G9OCiyCTCHSyfsE3g7tks33NZ8O8gF8xa9OmU9TQPwwAyUr6JQXz0CW77o7
Cr9LpHuNAgMBAAECggEBAJRbMbtfqc8XqDYjEfGur2Lld19Pb0yl7RbvD3NjYhDR
X2DqPyhaRfg5fWubGSp4jyBz6C5qJwMsVN80DFNm83qoj7T52lC6aoOaV6og3V8t
SIZzxLUyXKdpRxM5kR13HSHmeQYkPbi9HcrRM/1PqdzTMXNuyQl3wq9oZDAJchsf
fmoh080htkaxhEb1bMXa2Lj7j2OIkHOsQeIu6BdbxIKRPIT+zrcklE6ocW8fTWAS
Qi3IZ1FYLL+fs6TTxjx0VkC8QLaxWxY0pqTiwS7ndZiZKc3l3ARuvRk8buP+X3Jg
BD86FQ18OXZC9boMbDbzv2cOLtdkq5pS3lJE4F9gjYECgYEA69ukU2pNWot2OPwK
PuPwAXWNrvnvFzQgIc0qOiCmgKJU6wqunlop4Bx5XmetHExVyJVBEhaHoDr0F3Rs
gt8IclKDsWGXoVcgfu3llMimiZ05hOf/XtcGTCZwZenMQ30cFh4ZRuUu7WCZ9tqO
28P8jCXB3IcaRpRnNvVvmCr5NXECgYEA09nUzRW993SlohceRW2C9fT9HZ4BaPWO
5wVlnoo5mlUfAyzl+AGT/WlKmrn/1gAHIznQJ8ZIABQvPaBXhvkANXZP5Ie0lObw
jA7qFuKt7yV4GGlDnU1MOLh+acABMQBGSx8BJDaomH7glTiPEPTZjoP6wfAsd1uv
Knjt7jH2ad0CgYEAx9ghknRd+rx0fbBBVix4riPW20324ihOmZVnlD0aF6B0Z3tz
ncUz+irmQ7GBIpsjjIO60QK6BHAvZrhFQVaNp6B26ZORkSlr5WDZyImDYtMPa6fP
36I+OcPQNOo3I3Acnjj+ne2PJ59Ula92oIudr3pGmv72qpsQIacw2TSAWGECgYEA
sdNAN+HPMn68ZaGoLDjvW8uIB6tQnay5hhvWn8yA65YV0RGH+7Q/Z9BQ6i3EnPor
A5uMqUZbu4011jHYJpiuXzHvf/GVWAO92KLQReOCgqHd/Aen1MtEdrwOiG+90Ebd
ukLNL3ud61tc4oS2OlJ8p48LFm2mtY3FLA6UEYPoxhUCgYEAtsfWIGnBh7XC+HwI
2higSgN92VpJHSPOyOi0aG/u5AEQ+fsCUIi3KakxzvmiGMAEvWItkKyz2Gu8smtn
2HVsGxI5UW7aLw9s3qe8kyMSfUk6pGamVhJUQmDr77+5zEzykPBxwGwDwdeR43CR
xVgf/Neb/avXgIgi6drj8dp1fWA=
-----END PRIVATE KEY-----
        """
        rsa_priv_key = RSA.importKey(self.pem_priv_key)
        self.priv_key = PKCS1_v1_5.new(rsa_priv_key)
        self.pub_key = PKCS1_v1_5.new(rsa_priv_key.publickey())

        self.tls_ctx = tlsc.TLSSessionCtx()
        self.tls_ctx.rsa_load_keys(self.pem_priv_key)
        # SSLv2
        self.record_version = 0x0002
        # TLSv1.0
        self.hello_version = 0x0301
        # RSA_WITH_RC4_128_SHA
        self.cipher_suite = 0x5
        # DEFLATE
        self.comp_method = 0x1
        self.client_hello = tls.TLSRecord(version=self.record_version)/tls.TLSHandshake()/tls.TLSClientHello(version=self.hello_version, compression_methods=[self.comp_method], cipher_suites=[self.cipher_suite])
        self.tls_ctx.insert(self.client_hello)
        self.server_hello = tls.TLSRecord(version=self.hello_version)/tls.TLSHandshake()/tls.TLSServerHello(version=self.hello_version, compression_method=self.comp_method, cipher_suite=self.cipher_suite)
        self.tls_ctx.insert(self.server_hello)
        # Build method to generate EPMS automatically in TLSSessionCtx
        self.client_kex = tls.TLSRecord(version=self.hello_version)/tls.TLSHandshake()/tls.TLSClientKeyExchange()/self.tls_ctx.get_encrypted_pms()
        self.tls_ctx.insert(self.client_kex)
        unittest.TestCase.setUp(self)

    def test_invalid_tls_session_context_raises_error(self):
        with self.assertRaises(ValueError):
            tls.to_raw(None, None)

    def test_unsupported_layer_raises_error(self):
        pkt = tls.TLSClientHello()
        with self.assertRaises(KeyError):
            tls.to_raw(pkt, self.tls_ctx)

    def test_record_payload_is_identical_to_raw_payload(self):
        pkt = tls.TLSPlaintext(data=b"ABCD")
        raw = tls.to_raw(pkt, self.tls_ctx)
        record = tls.TLSRecord()/raw
        # Length not set, until after scapy build() is called
        #self.assertEqual(record[tls.TLSRecord].length, len(raw))
        self.assertEqual(str(record[tls.TLSRecord].payload), raw)

    def test_all_hooks_are_called_when_defined(self):
        # Return the data twice, but do not compress
        def custom_compress(comp_method, pre_compress_data):
            return pre_compress_data * 2
        # Return cleartext, null mac, null padding
        pre_encrypt = lambda x: (x, b"", b"")
        # Return cleartext
        encrypt = lambda x, y, z: x
        data = b"ABCD"
        pkt = tls.TLSPlaintext(data=data)
        raw = tls.to_raw(pkt, self.tls_ctx, compress_hook=custom_compress, pre_encrypt_hook=pre_encrypt, encrypt_hook=encrypt)
        self.assertEqual(len(raw), len(data) * 2)
        self.assertEqual(raw, data * 2)

    def test_tls_record_header_is_updated_when_output(self):
        data = b"ABCD" * 389
        pkt = tls.TLSPlaintext(data=data)
        # Use server side keys, include TLSRecord header in output
        record = tls.to_raw(pkt, self.tls_ctx, client=False, include_record=True)
        self.assertTrue(record.haslayer(tls.TLSRecord))
        self.assertEqual(record.content_type, 0x17)
        self.assertEqual(record.version, self.tls_ctx.params.negotiated.version)

class TestTLSCertificate(unittest.TestCase):
    
    def setUp(self):
        '''
        //default openssl 1.0.1f server.pem
        subject= C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = Test Server Cert
        issuer= C = UK, O = OpenSSL Group, OU = FOR TESTING PURPOSES ONLY, CN = OpenSSL Test Intermediate CA
        '''
        rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+',re.DOTALL)
        self.pem_cert = """-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"""
        self.der_cert = rex_pem.findall(self.pem_cert)[0].decode("base64")
        self.pem_priv_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA84TzkjbcskbKZnrlKcXzSSgi07n+4N7kOM7uIhzpkTuU0HIv
h4VZS2axxfV6hV3CD9MuKVg2zEhroqK1Js5n4ke230nSP/qiELfCl0R+hzRtbfKL
tFUr1iHeU0uQ6v3q+Tg1K/Tmmg72uxKrhyHDL7z0BriPjhAHJ5XlQsvR1RCMkqzu
D9wjSInJxpMMIgLndOclAKv4D1wQtYU7ZpTw+01XBlUhIiXb86qpYL9NqnnRq5JI
uhmOEuxo2ca63+xaHNhD/udSyc8C0Md/yX6wlONTRFgLLv0pdLUGm1xEjfsydaQ6
qGd7hzIKUI3hohNKJa/mHLElv7SZolPTogK/EQIDAQABAoIBAADq9FwNtuE5IRQn
zGtO4q7Y5uCzZ8GDNYr9RKp+P2cbuWDbvVAecYq2NV9QoIiWJOAYZKklOvekIju3
r0UZLA0PRiIrTg6NrESx3JrjWDK8QNlUO7CPTZ39/K+FrmMkV9lem9yxjJjyC34D
AQB+YRTx+l14HppjdxNwHjAVQpIx/uO2F5xAMuk32+3K+pq9CZUtrofe1q4Agj9R
5s8mSy9pbRo9kW9wl5xdEotz1LivFOEiqPUJTUq5J5PeMKao3vdK726XI4Z455Nm
W2/MA0YV0ug2FYinHcZdvKM6dimH8GLfa3X8xKRfzjGjTiMSwsdjgMa4awY3tEHH
674jhAECgYEA/zqMrc0zsbNk83sjgaYIug5kzEpN4ic020rSZsmQxSCerJTgNhmg
utKSCt0Re09Jt3LqG48msahX8ycqDsHNvlEGPQSbMu9IYeO3Wr3fAm75GEtFWePY
BhM73I7gkRt4s8bUiUepMG/wY45c5tRF23xi8foReHFFe9MDzh8fJFECgYEA9EFX
4qAik1pOJGNei9BMwmx0I0gfVEIgu0tzeVqT45vcxbxr7RkTEaDoAG6PlbWP6D9a
WQNLp4gsgRM90ZXOJ4up5DsAWDluvaF4/omabMA+MJJ5kGZ0gCj5rbZbKqUws7x8
bp+6iBfUPJUbcqNqFmi/08Yt7vrDnMnyMw2A/sECgYEAiiuRMxnuzVm34hQcsbhH
6ymVqf7j0PW2qK0F4H1ocT9qhzWFd+RB3kHWrCjnqODQoI6GbGr/4JepHUpre1ex
4UEN5oSS3G0ru0rC3U4C59dZ5KwDHFm7ffZ1pr52ljfQDUsrjjIMRtuiwNK2OoRa
WSsqiaL+SDzSB+nBmpnAizECgYBdt/y6rerWUx4MhDwwtTnel7JwHyo2MDFS6/5g
n8qC2Lj6/fMDRE22w+CA2esp7EJNQJGv+b27iFpbJEDh+/Lf5YzIT4MwVskQ5bYB
JFcmRxUVmf4e09D7o705U/DjCgMH09iCsbLmqQ38ONIRSHZaJtMDtNTHD1yi+jF+
OT43gQKBgQC/2OHZoko6iRlNOAQ/tMVFNq7fL81GivoQ9F1U0Qr+DH3ZfaH8eIkX
xT0ToMPJUzWAn8pZv0snA0um6SIgvkCuxO84OkANCVbttzXImIsL7pFzfcwV/ERK
UM6j0ZuSMFOCr/lGPAoOQU0fskidGEHi1/kW+suSr28TqsyYZpwBDQ==
-----END RSA PRIVATE KEY-----
        """
        self.der_priv_key = rex_pem.findall(self.pem_priv_key)[0].decode("base64")
        unittest.TestCase.setUp(self)
        
    def test_tls_certificate_x509(self):
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSCertificateList(certificates=[tls.TLSCertificate(data=x509.X509Cert(self.der_cert))])
        
        self.assertEqual(str(pkt[tls.TLSCertificateList].certificates[0].data), self.der_cert)
        self.assertEqual(str(pkt[tls.TLSCertificate].data), self.der_cert)
        try:
            pkt[tls.TLSCertificate].data.pubkey
        except AttributeError, ae:
            self.fail(ae)
        # serialize and dissect the same packet
        pkt_d = tls.SSL(str(pkt))
        self.assertEqual(str(pkt_d[tls.TLSCertificateList].certificates[0].data), self.der_cert)
        self.assertEqual(str(pkt_d[tls.TLSCertificate].data), self.der_cert)
        try:
            pkt_d[tls.TLSCertificate].data.pubkey
        except AttributeError, ae:
            self.fail(ae)
        # compare pubkeys
        self.assertEqual(pkt[tls.TLSCertificate].data.pubkey, pkt_d[tls.TLSCertificate].data.pubkey)
        
    def test_tls_certificate_x509_pubkey(self):
        pkt = tls.TLSRecord()/tls.TLSHandshake()/tls.TLSCertificateList(certificates=[tls.TLSCertificate(data=x509.X509Cert(self.der_cert))])
        # dissect and extract pubkey
        pkt = tls.SSL(str(pkt)) 
        
        pubkey_extract_from_der = tlsc.x509_extract_pubkey_from_der(self.der_cert)
        pubkey_extract_from_tls_certificate = tlsc.x509_extract_pubkey_from_der(pkt[tls.TLSCertificate].data)
        
        self.assertEqual(pubkey_extract_from_der, pubkey_extract_from_tls_certificate)

if __name__ == "__main__":
    unittest.main()
