import socket

def main():
    HOST = '127.0.0.1'
    PORT = 18927

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")

            while True:
                message = input("Enter message to send (or 'quit' to exit): ")
                if message.lower() == 'quit':
                    break
                
                client_socket.sendall(message.encode())
                print(f"Sent: {message}")
                
                response = client_socket.recv(1024).decode()
                print(f"Server response: {response}")
        except KeyboardInterrupt:
            print("\nClient shutting down.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Connection closed.")

if __name__ == "__main__":
    main()
