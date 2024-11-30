import selectors
import socket
from message_handler import MessageHandler
from logger import logger
from protocol import RequestType

class ConnectionClosed(Exception):
  pass

class SocketManager:
    def __init__(self, selector: selectors.BaseSelector) -> None:
        self.selector = selector
        self.clients: dict[socket.socket, dict[str, str]] = {}
        self.message_handler = MessageHandler()  # Initialize MessageHandler instance

    def register_client(self, conn: socket.socket, addr: str) -> None:
        data = {'addr': addr, 'allowed_requests': [RequestType.CONNECT]}
        self.clients[conn] = data
        self.selector.register(conn, selectors.EVENT_READ, data)
        logger.debug(f"SocketManager - Registered client {addr}")

    def handle_client(self, key: selectors.SelectorKey, mask: int) -> None:
        conn: socket.socket = key.fileobj
        state: dict[str, str] = key.data

        try:
            if mask & selectors.EVENT_READ:
                try:
                    logger.debug(f"SocketManager - Received data from {state['addr']}")
                    message_length = int.from_bytes(conn.recv(2), 'big')
                    logger.debug(f"SocketManager - Message length from {state['addr']} is {message_length}")
                    received_data = self.recv_exact(conn, message_length)
                    logger.debug(f"SocketManager - Received full message from {state['addr']}")
                    response = self.message_handler.handle_message(received_data, state)
                    logger.debug(f"SocketManager - Handled message from {state['addr']}")
                    response_length_bytes = len(response).to_bytes(2, 'big')
                    data_to_send = response_length_bytes + response
                    logger.info(f"SocketManager - Sending response to {state['addr']}")
                    conn.sendall(data_to_send)
                    logger.info(f"SocketManager - Sent response to {state['addr']}")
                except ConnectionClosed:
                    self.unregister_client(conn)
                    return
        except ConnectionClosed as e:
            logger.warning(f"Connection with {state['addr']} closed mid-message: {e}")
            self.unregister_client(conn)
        except Exception as e:
            logger.error(f"Unexpected error with client {state['addr']}: {e}")
            self.unregister_client(conn)

    def unregister_client(self, conn: socket.socket) -> None:
        """Unregister a client from the selector and close the connection."""
        addr = self.clients.pop(conn, {}).get('addr', 'Unknown')
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
