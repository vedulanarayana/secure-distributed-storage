from client.chunker import chunk_bytes, hash_ciphertext
from client.crypto import encrypt_chunk, generate_file_key


def test_chunk_bytes_respects_size():
    data = b"x" * 10
    chunks = list(chunk_bytes(data, chunk_size=4))
    assert chunks == [b"xxxx", b"xxxx", b"xx"]


def test_ciphertext_hash_no_collision_for_identical_plaintext():
    key = generate_file_key()
    plaintext = b"same content twice"
    _, ct1 = encrypt_chunk(key, plaintext)
    _, ct2 = encrypt_chunk(key, plaintext)
    assert hash_ciphertext(ct1) != hash_ciphertext(ct2)
