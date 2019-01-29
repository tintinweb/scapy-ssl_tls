import Cryptodome.Util.number
from Cryptodome.Util.number import ceil_div, bytes_to_long, long_to_bytes

class multidigest_pkcs1_15:

    def __init__(self, rsa_key):
        self._key = rsa_key

    def sign(self, msg_digest):
        modBits = Cryptodome.Util.number.size(self._key.n)
        k = ceil_div(modBits, 8)  # Convert from bits to bytes

        ps = b'\xFF' * (k - len(msg_digest) - 3)
        em = b'\x00\x01' + ps + b'\x00' + msg_digest
        em_int = bytes_to_long(em)
        m_int = self._key._decrypt(em_int)
        signature = long_to_bytes(m_int, k)
        return  signature

def new(rsa_key):
    return multidigest_pkcs1_15(rsa_key)