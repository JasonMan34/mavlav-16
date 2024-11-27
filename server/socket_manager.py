import threading

class SocketManager:
    def __init__(self, server_socket):
        self.server_socket = server_socket
        self.clients = []

    def handle_client(self, conn, addr):
        """
        Handles communication with a connected client.  
        Runs in a separate thread for each client.
        """
        self.clients.append((conn, addr))
        client_thread = threading.Thread(target=self._client_handler, args=(conn, addr))
        client_thread.daemon = True  # Close the thread when the main program exits
        client_thread.start()

    def _client_handler(self, conn, addr):
        try:
            with conn:
                print(f"Handling client {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received from {addr}: {data.decode()}")

                    response = f"Server received: {data.decode()}"
                    conn.sendall(response.encode())
        except Exception as e:
            print(f"Error with client {addr}: {e}")
        finally:
            print(f"Connection with {addr} closed")
            self.clients.remove((conn, addr))
