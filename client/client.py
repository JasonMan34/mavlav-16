import time
import socket
from logger import logger
from protocol import RequestType

class ConnectionClosed(Exception):
    pass

def recv_exact(conn: socket.socket, size: int) -> bytes:
    """Receives exactly `size` bytes from the socket."""
    received_data = bytearray()
    logger.debug(f"Starting to receive exactly {size} bytes")
    while len(received_data) < size:
        chunk = conn.recv(size - len(received_data))
        if not chunk:
            raise ConnectionClosed(f"Failed to receive the expected bytes from the socket (received {len(received_data)} out of {size}).")
        logger.debug(f"Received {len(chunk)} bytes out of {size}")
        received_data.extend(chunk)
    return bytes(received_data)

HOST = '127.0.0.1'
PORT = 18927

def main():
    # Create a socket and connect to the server
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
            logger.info(f"Connected to server at {HOST}:{PORT}")

            while True:
                message = input("Enter message to send (or 'quit' to exit): ")
                if message.lower() == 'quit':
                    break

                message_bytes = message.encode()
                message_length = len(message_bytes) + 1
                message_length_bytes = message_length.to_bytes(2, 'big')
                data_to_send = message_length_bytes + bytes([RequestType.CONNECT]) + message_bytes
                logger.info(f"Sending message: {data_to_send}")
                client_socket.sendall(data_to_send)
                logger.info(f"Message sent")

                # Receive the response from the server
                response_length = int.from_bytes(client_socket.recv(2), 'big')
                logger.info(f"Received response length: {response_length}")
                response_data = recv_exact(client_socket, response_length)
                response = response_data.decode()
                logger.info(f"Server response: {response}")
        except ConnectionClosed as e:
            logger.warning(f"Connection with server unexpectedly closed: {e}")
        except KeyboardInterrupt:
            logger.info("\nClient shutting down.")
        except Exception as e:
            logger.error(f"An error occurred: {e}")
        finally:
            logger.info("Connection closed.")

if __name__ == "__main__":
    logger.debug("Main function called")
    main()
