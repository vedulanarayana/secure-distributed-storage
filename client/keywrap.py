from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZE = 4096

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def wrap_key(public_key: rsa.RSAPublicKey, aes_key: bytes) -> bytes:
    return public_key.encrypt(aes_key, _OAEP)


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped_key: bytes) -> bytes:
    return private_key.decrypt(wrapped_key, _OAEP)


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(
    private_key: rsa.RSAPrivateKey, password: bytes | None = None
) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("expected an RSA public key")
    return key


def load_private_key(pem: bytes, password: bytes | None = None) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("expected an RSA private key")
    return key
