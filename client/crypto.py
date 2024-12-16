from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey 
from cryptography.hazmat.primitives.asymmetric import ec 
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.backends import default_backend
from base64 import *

def generate_ec_keypair() -> tuple[EllipticCurvePublicKey, EllipticCurvePrivateKey]: 
    private_key = ec.generate_private_key(ec.SECP256R1()) 
    public_key = private_key.public_key() 
    return [public_key, private_key]

def get_pem(ec_public_key: EllipticCurvePublicKey) -> bytes:
    return ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

#for symmetric key
def create_shared_secret(our_private_key: EllipticCurvePrivateKey, their_public_key: EllipticCurvePublicKey) -> bytes: 
    return our_private_key.exchange(ec.ECDH(), their_public_key) 

def wrap_aes_key_with_derived_key(aes_key: bytes, derived_key: bytes) -> bytes: 
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB()) 
    encryptor = cipher.encryptor() 
    return encryptor.update(aes_key) + encryptor.finalize() 

def unwrap_aes_key_with_derived_key(aes_key: bytes, derived_key: bytes) -> bytes: 
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB()) 
    decryptor = cipher.decryptor() 
    return decryptor.update(aes_key) + decryptor.finalize() 

def do_kdf(shared_secret: bytes) -> bytes: 
    salt = b'stam'
    kdf = PBKDF2HMAC( 
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=salt, 
        iterations=1000000, 
    ) 
    return kdf.derive(shared_secret) 
# POC

my_pub, my_priv = generate_ec_keypair()
your_pub, your_priv = generate_ec_keypair()


# Test code :)
if __name__ == "__main__":
    # should be the same
    print(b64encode(create_shared_secret(my_priv, your_pub)).decode())
    print(b64encode(create_shared_secret(your_priv, my_pub)).decode())
    print(create_shared_secret(my_priv, your_pub))
    print(do_kdf(create_shared_secret(my_priv, your_pub)))