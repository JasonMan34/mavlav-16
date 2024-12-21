from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from protocol import RequestType


class ClientState:
    def __init__(self, addr: str):
        self.addr: str = addr
        self.allowed_requests: list[RequestType] = [RequestType.VERIFY_SERVER_IDENTITY]
        self.phone_number: str | None = None
        self.digits: str | None = None
        self.sign_up_attempts: int = 0
        self.public_key_bytes: bytes | None = None
        self.public_key: EllipticCurvePublicKey | None = None
        self.sign_in_challenge: bytes | None = None

