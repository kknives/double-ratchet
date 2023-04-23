from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def hkdf(inp, length):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'', info=b'',
    backend=default_backend())
    return hkdf.derive(inp)
class SymmetricRatchet():
    def __init__(self, root):
        self.state = root
    def next(self, inp):
        output = hkdf(self.state+inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv

