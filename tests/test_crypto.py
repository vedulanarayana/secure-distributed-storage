import pytest
from cryptography.exceptions import InvalidTag

from client.crypto import decrypt_chunk, encrypt_chunk, generate_file_key


def test_round_trip():
    key = generate_file_key()
    plaintext = b"hello distributed storage"
    nonce, ciphertext = encrypt_chunk(key, plaintext)
    assert decrypt_chunk(key, nonce, ciphertext) == plaintext


def test_wrong_key_fails_decryption():
    key = generate_file_key()
    other_key = generate_file_key()
    nonce, ciphertext = encrypt_chunk(key, b"secret payload")
    with pytest.raises(InvalidTag):
        decrypt_chunk(other_key, nonce, ciphertext)


def test_tampered_ciphertext_fails_decryption():
    key = generate_file_key()
    nonce, ciphertext = encrypt_chunk(key, b"secret payload")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
    with pytest.raises(InvalidTag):
        decrypt_chunk(key, nonce, tampered)


def test_identical_plaintext_yields_different_ciphertext():
    key = generate_file_key()
    plaintext = b"repeated content block"
    _, ct1 = encrypt_chunk(key, plaintext)
    _, ct2 = encrypt_chunk(key, plaintext)
    assert ct1 != ct2
