class Client:
    def __init__(self, phone_number: str, public_key: bytes):
        self.phone_number = phone_number
        self.public_key = public_key

registered_clients: dict[str, Client] = {}

def is_client_registered(phone_number: str) -> bool:
    return phone_number in registered_clients

def register_client(phone_number: str, public_key):
    registered_clients[phone_number] = Client(phone_number, public_key)

def get_public_key(phone_number: str):
    recipient = registered_clients.get(phone_number, None)  
    return recipient.public_key if recipient else None 