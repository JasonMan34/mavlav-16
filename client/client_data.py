import os
import pickle
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey 
from crypto import generate_ec_keypair, load_private_key, load_public_key, private_key_to_pem, public_key_to_pem
from logger import logger


DATA_FILE_PATH = "client_data.pkl"

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
            self.private_key_bytes: bytes | None = None
            self.private_key: EllipticCurvePrivateKey | None = None
            self.public_key_bytes: bytes | None = None
            self.public_key: EllipticCurvePublicKey | None = None
            self.contacts: dict[str, tuple[bytes, bytes, bytes]] = {}
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
                    
                    self.private_key_bytes = data.get('private_key_bytes')
                    self.public_key_bytes = data.get('public_key_bytes')
                    
                    if self.phone_number is None or self.is_signed_up is None or self.private_key_bytes is None or self.public_key_bytes is None:
                        logger.warning("client.data file is corrupted, creating new client data.")
                        self.create_new_client()
                    else:
                        self.private_key = load_private_key(self.private_key_bytes)
                        self.public_key = load_public_key(self.public_key_bytes)
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
        self.public_key_bytes = public_key_to_pem(self.public_key)
        self.private_key_bytes = private_key_to_pem(self.private_key)
        self.is_signed_up = False
    
    def save_data(self):
        """Save the current client data to the file using pickle."""
        try:
            with open(DATA_FILE_PATH, "wb") as file:
                data = {
                    'phone_number': self.phone_number,
                    'is_signed_up': self.is_signed_up,
                    'private_key_bytes': self.private_key_bytes,
                    'public_key_bytes': self.public_key_bytes
                }

                pickle.dump(data, file)
                logger.debug("Client data saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save client data: {e}")
            exit(1)

client_data = ClientData()
