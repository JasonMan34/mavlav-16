import socket
import selectors
from socket_manager import SocketManager

def main() -> None:
    HOST = '0.0.0.0'
    PORT = 18927

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        server_socket.setblocking(False)
        print(f"Server is running on {HOST}:{PORT}")

        selector: selectors.DefaultSelector = selectors.DefaultSelector()
        server_socket_key: selectors.SelectorKey = selector.register(server_socket, selectors.EVENT_READ, data=None)
        socket_manager: SocketManager = SocketManager(selector)

        try:
            while True:
                events = selector.select(0.5)
                for key, mask in events:
                    if key == server_socket_key:
                        # Accept new client connections
                        conn, addr = server_socket.accept()
                        print(f"Connection accepted from {addr}")
                        conn.setblocking(False)
                        socket_manager.register_client(conn, addr)
                    else:
                        socket_manager.handle_client(key, mask)
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        except Exception as e:
            print(f"Server encountered an error: {e}")

if __name__ == "__main__":
    main()

