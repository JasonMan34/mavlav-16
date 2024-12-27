import os
from crypto import *
from logger import logger

CLIENT_INFO_FILE = "client_info.txt"
LEN_PHONE_NUM = 10
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
            self.public_key_bytes: bytes | None = None
            self.contacts: dict[str, tuple[bytes, bytes, bytes]] = {}
            self.load_data()
            self._initialized = True

    def load_data(self):
        """Load the client data from the file if it exists."""
        if os.path.exists(CLIENT_INFO_FILE):
            try:
                with open(CLIENT_INFO_FILE, "r") as info_file:
                    client_info = info_file.readline()
                    delimiter = client_info.find(":")
                    if delimiter != -1:
                        self.phone_number = client_info[:delimiter]
                        self.is_signed_up = client_info[delimiter+1:].strip() == "1"

                    if delimiter == -1 or self.phone_number is None or len(self.phone_number)!=LEN_PHONE_NUM:
                        logger.warning("client.data file is corrupted, creating new client data.")
                        self.get_phone_number()
                        self.is_signed_up = False

                    if self.is_signed_up:    
                        self.private_key_bytes = info_file.read().encode()
                        self.public_key_bytes = get_public_from_private(self.private_key_bytes)
                    else:
                        self.generate_keys()
                    
                    
                logger.debug(f"Loaded existing data for phone number {self.phone_number}")
            except Exception as e:
                logger.error(f"Failed to load client data: {e}")
                self.get_phone_number()
                self.generate_keys()
        else:
            logger.debug("No existing data found, creating new client data.")
            self.get_phone_number()
            self.generate_keys()
    
    def get_phone_number(self):
        """Create a new client and ask the user for necessary information."""
        self.phone_number = input(f"Please enter your phone number ({LEN_PHONE_NUM} digits): ").strip()
        while len(self.phone_number) != LEN_PHONE_NUM or not self.phone_number.isdigit():
            print(f"Invalid phone number. Please enter a {LEN_PHONE_NUM}-digit phone number.")
            self.phone_number = input(f"Please enter your phone number ({LEN_PHONE_NUM} digits): ").strip()

    def generate_keys(self):
        self.public_key_bytes, self.private_key_bytes = generate_ec_keypair()
        logger.info("Generated EC key pair")
        self.is_signed_up = False
    
    def save_data(self):
        """Save the current client data to the file using pickle."""
        try:
            with open(CLIENT_INFO_FILE, "w") as file:
                signed_up = 1 if self.is_signed_up else 0
                data = f"{self.phone_number}:{signed_up}\n{self.private_key_bytes.decode()}"
                file.write(data)
                logger.debug("Client data saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save client data: {e}")
            exit(1)

client_data = ClientData()
