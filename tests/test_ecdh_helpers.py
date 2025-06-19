# tests/test_ecdh_helpers.py
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.fernet import Fernet

from ECDH_Prototype import generate_key_pair, derive_fernet_key

def test_ecdh_sanity_shared_secret():
    """
    Make sure two freshly generated key pairs produce the same shared secret,
    and print the private values and derived secrets for inspection.
    """
    a = generate_key_pair()
    b = generate_key_pair()

    # Extract and print private scalar values
    priv_a = a.private_numbers().private_value
    priv_b = b.private_numbers().private_value
    print(f"Private scalar A: {priv_a}")
    print(f"Private scalar B: {priv_b}")

    shared_ab = a.exchange(ec.ECDH(), b.public_key())
    shared_ba = b.exchange(ec.ECDH(), a.public_key())

    # Print shared secret in hex form
    print(f"Shared secret A→B: {shared_ab.hex()}")
    print(f"Shared secret B→A: {shared_ba.hex()}")

    assert shared_ab == shared_ba

def test_derive_fernet_key_length_and_type():
    """
    Derived key should be 44-byte URL-safe base64 and of type bytes.
    Print the derived key for verification.
    """
    dummy = b"\x00" * 32
    key = derive_fernet_key(dummy)
    print(f"Derived Fernet key: {key}")

    assert isinstance(key, bytes)
    assert len(key) == 44

def test_fernet_encrypt_decrypt_roundtrip():
    """
    Ensure Fernet made from the derived key can round-trip encrypt/decrypt.
    Also print the generated token and decrypted output.
    """
    a = generate_key_pair()
    b = generate_key_pair()
    shared = a.exchange(ec.ECDH(), b.public_key())

    fkey = derive_fernet_key(shared)
    print(f"Using Fernet key: {fkey}")

    f = Fernet(fkey)
    plaintext = b"hello, world"
    token = f.encrypt(plaintext)

    # Print the token and the decrypted result
    print(f"Fernet token: {token}")
    decrypted = f.decrypt(token)
    print(f"Decrypted text: {decrypted}")

    assert decrypted == plaintext
