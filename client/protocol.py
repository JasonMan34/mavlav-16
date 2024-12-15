import enum


class RequestType(enum.Enum):
    CONNECTION_CLOSED = 0
    SIGN_UP = 1
    SIGN_UP_CONFIRM = 2
    SIGN_IN = 3


# 0-127: Good
# 128-255: Bad
class ResponseType(enum.Enum):
    SIGN_UP_STARTED = 1
    SIGN_UP_SUCCESS = 2
    REQUEST_TYPE_NOT_ALLOWED = 128
    PHONE_NUMBER_ALREADY_REGISTERED = 129
    SIGN_UP_WRONG_DIGITS = 130
    UNKNOWN_REQUEST_TYPE = 255