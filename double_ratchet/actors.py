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

        self.DHratchet = X25519PrivateKey.generate()

    def dh_ratchet(self, alice_public):
        dh_recv = self.DHratchet.exchange(alice_public)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print("[Bob]: recv ratchet seed", b64(shared_recv))

        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print("[Bob]: send ratchet seed", b64(shared_send))

    def x3dh(self, alice):
        dh1 = self.SignedPKb.exchange(alice.IdentityKa.public_key())
        dh2 = self.IdentityKb.exchange(alice.EKa.public_key())
        dh3 = self.SignedPKb.exchange(alice.EKa.public_key())
        dh4 = self.OnetimePKb.exchange(alice.EKa.public_key())

        self.sk = hkdf(dh1+dh2+dh3+dh4, 32)
        print("[Bob]: Shared key=",b64(self.sk))

    def init_ratchets(self):
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])

class Alice():
    def __init__(self):
        self.IdentityKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()

        self.DHratchet = None

    def dh_ratchet(self, bob_public):
        if self.DHratchet is not None:
            dh_recv = self.DHratchet.exchange(bob_public)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            self.recv_ratchet = SymmetricRatchet(shared_recv)
            print("[Alice]: recv ratchet seed", b64(shared_recv))

        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(bob_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print("[Alice]: send ratchet seed", b64(shared_send))

    def x3dh(self, bob: Bob):
        dh1 = self.IdentityKa.exchange(bob.SignedPKb.public_key())
        dh2 = self.EKa.exchange(bob.IdentityKb.public_key())
        dh3 = self.EKa.exchange(bob.SignedPKb.public_key())
        dh4 = self.EKa.exchange(bob.OnetimePKb.public_key())

        self.sk = hkdf(dh1+dh2+dh3+dh4, 32)
        print("[Alice]: Shared key=",b64(self.sk))

    def init_ratchets(self):
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])

