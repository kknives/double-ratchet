from double_ratchet.actors import Bob, Alice, b64

if __name__ == "__main__":
    alice = Alice()
    bob = Bob()
    alice.x3dh(bob)
    bob.x3dh(alice)
    if bob.sk != alice.sk:
        print("3DH Failure exiting...")
        exit(1)
    print("Key Exchange successful")

    alice.init_ratchets()
    bob.init_ratchets()
    print(f"""[Alice]: send ratchet={list(map(b64, alice.send_ratchet.next()))}
        , receive ratchet={list(map(b64, alice.recv_ratchet.next()))}""")
    print(f"""[Bob]: send ratchet={list(map(b64, bob.send_ratchet.next()))},
        receive ratchet={list(map(b64, bob.recv_ratchet.next()))}""")
