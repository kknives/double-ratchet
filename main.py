from .double_ratchet.actors import Bob, Alice

if __name__ == "__main__":
    alice = Alice()
    bob = Bob()
    alice.x3dh(bob)
    bob.x3dh(alice)
