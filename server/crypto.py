from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec 
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def generate_ec_keypair() -> tuple[EllipticCurvePublicKey, EllipticCurvePrivateKey]: 
    private_key = ec.generate_private_key(ec.SECP256R1()) 
    public_key = private_key.public_key() 
    return public_key, private_key

def get_pem(ec_public_key: EllipticCurvePublicKey) -> bytes:
    return ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_data: bytes) -> EllipticCurvePublicKey:
    return load_pem_public_key(pem_data, backend=default_backend())

def verify_signature(data: bytes, signature: bytes, public_key: EllipticCurvePublicKey) -> bool:
    return public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))