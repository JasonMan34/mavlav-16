import os
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from crypto import generate_ec_keypair
from logger import logger

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey 

DATA_FILE_PATH = "client.data"

class ClientData:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self.phone_number = None
            self.is_signed_up = False
            self.private_key: EllipticCurvePrivateKey | None = None
            self.public_key: EllipticCurvePublicKey | None = None
            self.contacts: dict  = {}
            # Try to load existing client data
            self.load_data()
            self._initialized = True

    def load_data(self):
        """Load the client data from the file if it exists."""
        if os.path.exists(DATA_FILE_PATH):
            try:
                with open(DATA_FILE_PATH, "rb") as file:
                    data = pickle.load(file)
                    
                    self.phone_number = data.get('phone_number')
                    self.is_signed_up = data.get('is_signed_up', False)
                    
                    if data.get('private_key') is not None:
                        self.private_key = serialization.load_pem_private_key(data=data.get('private_key'), password=None)
                    if data.get('public_key') is not None:
                        self.public_key = serialization.load_pem_public_key(data=data.get('public_key'))
                    
                    if self.phone_number is None or self.is_signed_up is None:
                        logger.warning("client.data file is corrupted, creating new client data.")
                        self.create_new_client()
                    else:
                        logger.debug(f"Loaded existing data for phone number {self.phone_number}")
            except Exception as e:
                logger.error(f"Failed to load client data: {e}")
                self.create_new_client()
        else:
            logger.debug("No existing data found, creating new client data.")
            self.create_new_client()
    
    def create_new_client(self):
        """Create a new client and ask the user for necessary information."""
        self.phone_number = input("Please enter your phone number (10 digits): ").strip()
        while len(self.phone_number) != 10 or not self.phone_number.isdigit():
            print("Invalid phone number. Please enter a 10-digit phone number.")
            self.phone_number = input("Please enter your phone number (10 digits): ").strip()
        
        self.public_key, self.private_key = generate_ec_keypair()
        self.is_signed_up = False
        
        # Save the data to a file
        self.save_data()
    
    def save_data(self):
        """Save the current client data to the file using pickle."""
        try:
            with open(DATA_FILE_PATH, "wb") as file:
                # Prepare the data to be serialized
                data = {
                    'phone_number': self.phone_number,
                    'is_signed_up': self.is_signed_up,
                    'private_key': self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ) if self.private_key is not None else None,
                    'public_key': self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ) if self.public_key is not None else None
                }
                # Serialize and save the data
                pickle.dump(data, file)
                logger.debug("Client data saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save client data: {e}")
            exit(1)

# Access the singleton instance
client_data = ClientData()
