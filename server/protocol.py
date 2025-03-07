import enum

class RequestType(enum.Enum):
    CONNECTION_CLOSED = 0
    VERIFY_SERVER_IDENTITY = 1
    SIGN_UP = 31
    SIGN_UP_CONFIRM = 32
    SIGN_IN = 41
    SIGN_IN_CONFIRM = 42
    INIT_MESSAGING = 61
    SEND_MESSAGE = 62
    RECEIVE_MESSAGES = 63

# 0-127: Good
# 128-255: Bad
class ResponseType(enum.Enum):
    CONNECTION_CLOSED = 0
    SERVER_IDENTITY_VERIFICATION = 1
    SIGN_UP_STARTED = 31
    SIGN_UP_SUCCESS = 32
    SIGN_IN_STARTED = 41
    SIGN_IN_SUCCESS = 42
    SENDING_REQUESTED_PUB_KEY = 61
    MESSAGE_SENT = 62
    HERE_ARE_YOUR_MESSAGES = 63
    REQUEST_TYPE_NOT_ALLOWED = 128
    SIGN_UP_FAILED_PHONE_NUMBER_ALREADY_REGISTERED = 131
    SIGN_UP_FAILED_WRONG_DIGITS = 132
    SIGN_UP_FAILED_TOO_MANY_ATTEMPTS = 133
    SIGN_UP_FAILED_INVALID_KEY = 134
    SIGN_IN_FAILED_PHONE_NUMBER_NOT_REGISTERED = 141
    RECIPIENT_PHONE_NOT_EXIST = 161
    INVALID_SIGNATURE = 251
    UNKNOWN_REQUEST_TYPE = 255
