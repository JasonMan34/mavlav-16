from protocol import RequestType


class ClientState:
    def __init__(self, addr: str):
        self.addr: str = addr
        self.allowed_requests: list[RequestType] = [RequestType.SIGN_UP, RequestType.SIGN_IN]
        self.phone_number: str | None = None
        self.digits: str | None = None
        self.public_key: bytes | None = None

