import selectors
import socket
from message_handler import MessageHandler
from logger import logger
from protocol import RequestType, ResponseType
from client_state import ClientState

# Secure!
def SendBySecureChannel(conn: socket.socket, data: bytes) -> None:
    conn.sendall(data)

class ConnectionClosed(Exception):
    pass

class InvalidRequestType(Exception):
    pass

class SocketManager:
    def __init__(self, selector: selectors.BaseSelector) -> None:
        self.selector = selector
        self.client_states: dict[socket.socket, ClientState] = {}
        self.message_handler = MessageHandler()

    def register_client(self, conn: socket.socket, addr: str) -> None:
        data = ClientState(addr)
        self.client_states[conn] = data
        self.selector.register(conn, selectors.EVENT_READ, data)
        logger.debug(f"SocketManager - Registered client {addr}")

    def receive_request_type(self, conn: socket.socket):
        raw_request_type = int.from_bytes(conn.recv(1), 'big')
        try:
            return RequestType(raw_request_type)
        except ValueError:
            raise InvalidRequestType(raw_request_type)

    def handle_client(self, key: selectors.SelectorKey, mask: int) -> None:
        conn: socket.socket = key.fileobj
        state: ClientState = key.data

        try:
            if mask & selectors.EVENT_READ:
                logger.debug(f"SocketManager - Received data from {state.addr}")
                request_type = self.receive_request_type(conn)
                logger.debug(f"SocketManager - Request type from {state.addr} is {request_type}")

                if request_type == RequestType.CONNECTION_CLOSED:
                    logger.info(f"Connection from {state.addr} was closed by the client")
                    self.unregister_client(conn)
                    return
                print(state.allowed_requests)
                if request_type not in state.allowed_requests:
                    logger.warning(f"SocketManager - Received disallowed request type {request_type} from {state.addr}")
                    response = self.message_handler.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)
                    conn.sendall(response)
                    return

                message_length = int.from_bytes(conn.recv(4), 'big')
                logger.debug(f"SocketManager - Message length from {state.addr} is {message_length}")
                received_data = self.recv_exact(conn, message_length)
                logger.debug(f"SocketManager - Received full message from {state.addr}")

                response = self.message_handler.handle_message(request_type, received_data, state)
                logger.debug(f"SocketManager - Handled message {request_type} from {state.addr}")
                conn.sendall(response)
                response_type = ResponseType(int.from_bytes(response[:1], 'big'))
                logger.info(f"SocketManager - Sent response {response_type.name} to {state.addr}")
                
                # Special use case, this code should be sent from some 3rd party service, but we're just gonna pretend and use
                # the same socket as a "secure channel", so we must do it from outside message_handler
                if request_type == RequestType.SIGN_UP and state.digits is not None:
                    SendBySecureChannel(conn, state.digits.encode())
        except InvalidRequestType as e:
            logger.warning(f"Received invalid request type from {state.addr}: {e}. Allowed requests are: {state.allowed_requests}")
            response = self.message_handler.generate_response(ResponseType.UNKNOWN_REQUEST_TYPE)
            conn.sendall(response)
        except ConnectionClosed as e:
            logger.warning(f"Connection with {state.addr} closed mid-message: {e}")
            self.unregister_client(conn)
        except Exception as e:
            logger.error(f"Unexpected error with client {state.addr}: {e}")
            self.unregister_client(conn)

    def unregister_client(self, conn: socket.socket) -> None:
        """Unregister a client from the selector and close the connection."""
        addr = self.client_states.pop(conn, {}).addr
        print(f"Connection with {addr} closed\n")
        self.selector.unregister(conn)
        conn.close()

    def recv_exact(self, conn: socket.socket, size: int) -> bytes:
        """Receives exactly `size` bytes from the socket."""
        logger.debug(f"SocketManager - Starting to receive exactly {size} bytes")
        received_data = bytearray()
        while len(received_data) < size:
            events = self.selector.select(timeout=1)
            for key, events in events:
                if key.fileobj == conn:
                    chunk = conn.recv(size - len(received_data))
                    if not chunk:
                        raise ConnectionClosed(f"Failed to receive the expected bytes from the socket.")
                    logger.debug(f"SocketManager - Received {len(chunk)} bytes out of {size}")
                    received_data.extend(chunk)
        return bytes(received_data)
