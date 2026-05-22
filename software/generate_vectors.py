from ascon import ascon_encrypt, ascon_decrypt, ascon_hash

def hx(data):
    return data.hex()

vectors = [
    {
        "name": "V1",
        "key": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "nonce": bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
        "ad": b"PSUT",
        "plaintext": b"Hello ASCON",
        "hash_input": b"Hardware Security"
    },
    {
        "name": "V2",
        "key": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "nonce": bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        "ad": b"ASCON Project",
        "plaintext": b"Test Vector Two",
        "hash_input": b"Lightweight Crypto"
    },
    {
        "name": "V3",
        "key": bytes.fromhex("0f0e0d0c0b0a09080706050403020100"),
        "nonce": bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
        "ad": b"Hardware",
        "plaintext": b"Third Message",
        "hash_input": b"ASCON Hash Test"
    }
]

for v in vectors:
    ciphertext, tag = ascon_encrypt(
        v["key"],
        v["nonce"],
        v["ad"],
        v["plaintext"],
        variant="Ascon-AEAD128"
    )

    ciphertext_tag = ciphertext + tag

    decrypted = ascon_decrypt(
        v["key"],
        v["nonce"],
        v["ad"],
        ciphertext_tag,
        variant="Ascon-AEAD128"
    )

    digest = ascon_hash(
        v["hash_input"],
        variant="Ascon-Hash256",
        hashlength=32
    )

    print("=" * 70)
    print(v["name"])
    print("KEY              =", hx(v["key"]))
    print("NONCE            =", hx(v["nonce"]))
    print("ASSOCIATED DATA  =", hx(v["ad"]))
    print("PLAINTEXT        =", hx(v["plaintext"]))
    print("CIPHERTEXT       =", hx(ciphertext))
    print("TAG              =", hx(tag))
    print("CIPHERTEXT+TAG   =", hx(ciphertext_tag))
    print("DECRYPTED        =", hx(decrypted))
    print("HASH INPUT       =", hx(v["hash_input"]))
    print("HASH OUTPUT      =", hx(digest))

    if decrypted == v["plaintext"]:
        print("DECRYPTION CHECK = PASS")
    else:
        print("DECRYPTION CHECK = FAIL")
