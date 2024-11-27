import socket
from socket_manager import SocketManager

def main():
    HOST = '0.0.0.0'
    PORT = 18927

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server is running on {HOST}:{PORT}")

        socket_manager = SocketManager(server_socket)

        try:
            while True:
                conn, addr = server_socket.accept()
                print(f"Connection accepted from {addr}")
                socket_manager.handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        except Exception as e:
            print(f"Server encountered an error: {e}")

if __name__ == "__main__":
    main()
