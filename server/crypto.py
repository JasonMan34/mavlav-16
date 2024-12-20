from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

def load_server_private_key() -> RSAPrivateKey:
    with open("server_private_key.pem", "rb") as key_file:
        return load_pem_private_key(key_file.read(), password=None)
    
server_private_key = load_server_private_key()

def load_public_key(pem_data: bytes) -> EllipticCurvePublicKey:
    return load_pem_public_key(pem_data, backend=default_backend())

def verify_signature(data: bytes, signature: bytes, public_key: EllipticCurvePublicKey) -> None:
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
