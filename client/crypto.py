from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey 
from cryptography.hazmat.primitives.asymmetric import ec 
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from base64 import b64encode
import os

def generate_ec_keypair() -> tuple[EllipticCurvePublicKey, EllipticCurvePrivateKey]: 
    """
        Generate asymmetric keys pair.
        :return: the public and private keys as a tuple in pem format (bytes)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return public_key, private_key

def public_key_to_pem(ec_public_key: EllipticCurvePublicKey) -> bytes:
    return ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def private_key_to_pem(ec_private_key: EllipticCurvePrivateKey) -> bytes:
    return ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  
        encryption_algorithm=serialization.NoEncryption() 
    )

def load_public_key(pem_data: bytes) -> EllipticCurvePrivateKey:
    return load_pem_public_key(pem_data, backend=default_backend())

def load_private_key(pem_data: bytes) -> EllipticCurvePrivateKey:
    return load_pem_private_key(pem_data, password=None, backend=default_backend())


def sign(data: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

# for symmetric key
def create_shared_secret(my_private_key_bytes: bytes, their_public_key_bytes: bytes) -> bytes: 
    my_private_key = load_private_key(my_private_key_bytes)
    their_public_key = load_public_key(their_public_key_bytes)
    return my_private_key.exchange(ec.ECDH(), their_public_key) 


def create_AES_key() -> tuple[bytes, bytes]:
    key = os.urandom(32) 
    iv = os.urandom(16) 
    return key, iv


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
    encryptor = cipher.encryptor() 
    pad = padding.PKCS7(128).padder()
    padded_message = pad.update(data) + pad.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize() 
    return ciphertext


def aes_cbc_decrypt(cipher_text: bytes, aes_key: bytes, iv:bytes) -> bytes: 
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv)) 
    decryptor = cipher.decryptor() 
    padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_message) + unpadder.finalize()
    return plaintext


def aes_ecb_encrypt(data: bytes, aes_key: bytes) -> bytes: 
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB()) 
    pad = padding.PKCS7(128).padder() 
    padded_message = pad.update(data) + pad.finalize()
    encryptor = cipher.encryptor() 
    return encryptor.update(padded_message) + encryptor.finalize() 


def aes_ecb_decrypt(cipher_text: bytes, aes_key: bytes) -> bytes: 
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB()) 
    decryptor = cipher.decryptor() 
    padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_message) + unpadder.finalize()
    return plaintext
