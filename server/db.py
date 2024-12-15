class Client:
    def __init__(self, phone_number: str, public_key):
        self.phone_number = phone_number
        self.public_key = public_key

registered_clients: dict[str, Client] = {}

def is_client_registered(phone_number: str) -> bool:
    return phone_number in registered_clients

def register_client(phone_number: str, public_key):
    registered_clients[phone_number] = Client(phone_number, public_key)