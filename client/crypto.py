import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


def generate_file_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_chunk(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt one plaintext chunk with a fresh random nonce.

    A fresh nonce per chunk means identical plaintext never produces
    identical ciphertext, so hashing the ciphertext for content addressing
    cannot collide across uploads.
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_chunk(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)
