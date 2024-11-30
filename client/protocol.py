class RequestType:
    CONNECT = 1
    DISCONNECT = 2
    MESSAGE = 3


# 0-127: Good
# 128-255: Bad
class ResponseType:
    UNKNOWN_REQUEST_TYPE = 128