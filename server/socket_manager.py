import selectors
import socket
from message_handler import MessageHandler
from logger import logger
from protocol import RequestType, ResponseType
from client_state import ClientState

class ConnectionClosed(Exception):
    pass

class InvalidMessageType(Exception):
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

    def receive_message_type(self, conn: socket.socket):
        raw_message_type = int.from_bytes(conn.recv(1), 'big')
        try:
            message_type = RequestType(raw_message_type)
            return message_type
        except ValueError:
            raise InvalidMessageType(raw_message_type)

    def handle_client(self, key: selectors.SelectorKey, mask: int) -> None:
        conn: socket.socket = key.fileobj
        state: ClientState = key.data

        try:
            if mask & selectors.EVENT_READ:
                logger.debug(f"SocketManager - Received data from {state.addr}")
                message_type = self.receive_message_type(conn)
                logger.debug(f"SocketManager - Message type from {state.addr} is {message_type}")
                if message_type not in state.allowed_requests:
                    logger.warning(f"SocketManager - Received disallowed message type {message_type} from {state.addr}")
                    response = self.message_handler.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)
                    conn.sendall(response)
                    return

                message_length = int.from_bytes(conn.recv(4), 'big')
                logger.debug(f"SocketManager - Message length from {state.addr} is {message_length}")
                received_data = self.recv_exact(conn, message_length)
                logger.debug(f"SocketManager - Received full message from {state.addr}")

                response = self.message_handler.handle_message(message_type, received_data, state)
                logger.debug(f"SocketManager - Handled message from {state.addr}")
                conn.sendall(response)
                logger.info(f"SocketManager - Sent response to {state.addr}")
                
                # Special use case, this code should be sent from some 3rd party service, but we're just gonna pretend and use
                # the same socket as a "secure channel", so we must do it from outside message_handler
                if message_type == RequestType.SIGN_UP and state.digits is not None:
                    conn.sendall(state.digits.encode())
        except InvalidMessageType as e:
            logger.warning(f"Received invalid message type from {state.addr}: {e}. Allowed requests are: {state.allowed_requests}")
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
        print(f"Connection with {addr} closed")
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
