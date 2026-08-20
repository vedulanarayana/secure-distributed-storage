import pytest

from client.crypto import generate_file_key
from client.keywrap import generate_keypair, unwrap_key, wrap_key


def test_wrap_unwrap_round_trip():
    private_key, public_key = generate_keypair()
    file_key = generate_file_key()
    wrapped = wrap_key(public_key, file_key)
    assert unwrap_key(private_key, wrapped) == file_key


def test_wrong_private_key_fails_unwrap():
    _, public_key = generate_keypair()
    other_private_key, _ = generate_keypair()
    wrapped = wrap_key(public_key, generate_file_key())
    with pytest.raises(ValueError):
        unwrap_key(other_private_key, wrapped)
