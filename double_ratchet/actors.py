import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

from .symmetric_ratchet import hkdf, SymmetricRatchet

b64 = lambda msg: base64.encodebytes(msg).decode('utf-8').strip()

class Bob():
    def __init__(self):
        self.IdentityKb = X25519PrivateKey.generate()
        self.SignedPKb = X25519PrivateKey.generate()
        self.OnetimePKb = X25519PrivateKey.generate()

    def x3dh(self, alice):
        dh1 = self.SignedPKb.exchange(alice.IdentityKa.public_key())
        dh2 = self.IdentityKb.exchange(alice.EKa.public_key())
        dh3 = self.SignedPKb.exchange(alice.EKa.public_key())
        dh4 = self.OnetimePKb.exchange(alice.EKa.public_key())

        self.sk = hkdf(dh1+dh2+dh3+dh4, 32)
        print("[Bob]: Shared key=",b64(self.sk))

class Alice():
    def __init__(self):
        self.IdentityKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()

    def x3dh(self, bob: Bob):
        dh1 = self.IdentityKa.exchange(bob.SignedPKb.public_key())
        dh2 = self.EKa.exchange(bob.IdentityKb.public_key())
        dh3 = self.EKa.exchange(bob.SignedPKb.public_key())
        dh4 = self.EKa.exchange(bob.OnetimePKb.public_key())

        self.sk = hkdf(dh1+dh2+dh3+dh4, 32)
        print("[Alice]: Shared key=",b64(self.sk))

