import selectors
import socket

class SocketManager:
    def __init__(self, selector: selectors.BaseSelector) -> None:
        self.selector = selector
        self.clients: dict[socket.socket, dict[str, str]] = {}

    def register_client(self, conn: socket.socket, addr: str) -> None:
        """
        Registers a new client connection with the selector.
        """
        data = {'addr': addr}
        self.clients[conn] = data
        self.selector.register(conn, selectors.EVENT_READ, data)

    def handle_client(self, key: selectors.SelectorKey, mask: int) -> None:
        """
        Handles communication with a connected client.
        """
        conn = key.fileobj
        data: dict[str, str] = key.data

        try:
            if mask & selectors.EVENT_READ:
                received_data: bytes = conn.recv(1024)
                if not received_data:
                    self.unregister_client(conn)
                    return

                print(f"Received from {data['addr']}: {received_data.decode()}")

                response: str = f"Server received: {received_data.decode()}"
                conn.sendall(response.encode())
        except Exception as e:
            print(f"Error with client {data['addr']}: {e}")
            self.unregister_client(conn)

    def unregister_client(self, conn: socket.socket) -> None:
        """
        Unregister a client from the selector and close the connection.
        """
        addr: str = self.clients.pop(conn, {}).get('addr', 'Unknown')
        print(f"Connection with {addr} closed")
        self.selector.unregister(conn)
        conn.close()

