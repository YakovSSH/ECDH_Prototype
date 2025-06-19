# tests/test_ecdh_helpers.py
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.fernet import Fernet

from ECDH_Prototype import generate_key_pair, derive_fernet_key

def test_ecdh_sanity_shared_secret():
    """
    Make sure two freshly generated key pairs produce the same shared secret.
    """
    a = generate_key_pair()
    b = generate_key_pair()

    shared_ab = a.exchange(ec.ECDH(), b.public_key())
    shared_ba = b.exchange(ec.ECDH(), a.public_key())

    assert shared_ab == shared_ba

def test_derive_fernet_key_length_and_type():
    """
    Derived key should be 44-byte URL-safe base64 and of type bytes.
    """
    dummy = b"\x00" * 32
    key = derive_fernet_key(dummy)
    assert isinstance(key, bytes)
    assert len(key) == 44

def test_fernet_encrypt_decrypt_roundtrip():
    """
    Ensure Fernet made from the derived key can round-trip encrypt/decrypt.
    """
    a = generate_key_pair()
    b = generate_key_pair()
    shared = a.exchange(ec.ECDH(), b.public_key())

    fkey = derive_fernet_key(shared)
    f = Fernet(fkey)
    plaintext = b"hello, world"
    token = f.encrypt(plaintext)
    assert f.decrypt(token) == plaintext
