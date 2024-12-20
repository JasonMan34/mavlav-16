from logger import logger
import pickle
import os

DB_FILE = "db.pkl"

class Client:
    def __init__(self, phone_number: str, public_key_bytes: bytes):
        self.phone_number = phone_number
        self.public_key_bytes = public_key_bytes

registered_clients: dict[str, Client] = {}
messages: dict[str, bytes] = {}

def save_db():
    """Save registered clients and messages to a file."""
    try:
        with open(DB_FILE, "wb") as f:
            pickle.dump((registered_clients, messages), f)
        logger.info("Database saved successfully.")
    except Exception as e:
        logger.error(f"Error saving database: {e}")

def load_db():
    """Load registered clients and messages from a file."""
    global registered_clients, messages
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "rb") as f:
                registered_clients, messages = pickle.load(f)
            logger.info("Database loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading database: {e}")
    else:
        logger.info("No database file found. Starting with empty database.")

def is_client_registered(phone_number: str) -> bool:
    return phone_number in registered_clients

def register_client(phone_number: str, public_key: bytes):
    registered_clients[phone_number] = Client(phone_number, public_key)
    messages[phone_number] = {}

def get_public_key_bytes(phone_number: str):
    recipient = registered_clients.get(phone_number, None)
    return recipient.public_key_bytes if recipient else None

# Load data at module initialization
load_db()
