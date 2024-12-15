class Client:
    def __init__(self, phone_number: str, public_key):
        self.phone_number = phone_number
        self.public_key = public_key

registered_clients: dict[str, Client] = {}

def is_client_signed_up(phone_number: str) -> bool:
    return phone_number in registered_clients