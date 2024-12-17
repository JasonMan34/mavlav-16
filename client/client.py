import socket
from client_data import client_data
from logger import logger
from protocol import RequestType, ResponseType
from crypto import *

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

def send_request(client_socket: socket.socket, request_type: RequestType, data: bytes) -> None:
    """
    Send a request to the server.
    
    :param client_socket: The socket connection to the server.
    :param request_type: The type of the request (e.g., SIGN_UP, SIGN_UP_CONFIRM).
    :param data: The data to send with the request (e.g., phone number, confirmation code).
    """
    # Prepare the data to send
    data_length_bytes = len(data).to_bytes(4, 'big')
    request_message = bytes([request_type.value]) + data_length_bytes + data

    # Send the request to the server
    logger.info(f"Sending {request_type.name} request with data: {data}")
    client_socket.sendall(request_message)
    logger.info("Request sent.")

def receive_response(client_socket: socket.socket):
    response_type_int = int.from_bytes(client_socket.recv(1), 'big')
    response_type = ResponseType(response_type_int)
    response_length = int.from_bytes(client_socket.recv(4), 'big')
    response_data = recv_exact(client_socket, response_length)
    return response_type, response_data

def sign_up(conn: socket.socket) -> None:
    # Send SIGN_UP request
    send_request(conn, RequestType.SIGN_UP, client_data.phone_number.encode())
    response_type, response_data = receive_response(conn)

    if response_type == ResponseType.PHONE_NUMBER_ALREADY_REGISTERED.value:
        logger.error("Phone number is already registered. Exiting.")
        exit(1)
    elif response_type == ResponseType.SIGN_UP_STARTED:
        logger.info("Sign-up process started. Waiting for confirmation code.")
    else:
        logger.error(f"Unexpected response from server: {response_type.name}")
        exit(1)

    # Handle confirmation
    confirmation_code_received = recv_exact(conn, 6).decode().strip()
    print(f"\n-- We interrupt this program to give you breaking news, straight from your phone! --")
    print(f"[PHONE] You have 1 new SMS message on your mobile device!")
    print(f"[PHONE] Confirmation code received from super secure server: {confirmation_code_received}")
    print(f"-- The program will now continue --\n")
    confirmation_code = input("Please Enter the confirmation code: ").strip()
    confirmation_data = confirmation_code.encode() + client_data.public_key
    send_request(conn, RequestType.SIGN_UP_CONFIRM, confirmation_data)
    response_type, response_data = receive_response(conn)

    if response_type == ResponseType.SIGN_UP_SUCCESS:
        client_data.is_signed_up = True
        logger.info("Sign-up successful!")
    elif response_type == ResponseType.SIGN_UP_WRONG_DIGITS:
        logger.error(f"Wrong confirmation code entered. Exiting. {response_type.name}")
    else:
        logger.error(f"Unexpected response from server: {response_type.name}")
        return

def send_msg(conn: socket.socket, recipient_phone: str, message: str):
    if recipient_phone in client_data.contacts:
        print(f"You have the contact {recipient_phone} set and ready for msging!")
    else:
        send_request(conn, RequestType.INIT_MSGING, recipient_phone.encode())
        response_type, response_data = receive_response(conn)
        print(response_type, response_data)
        if response_type != ResponseType.SENDING_REQUESTED_PUB_KEY:
            return
        public_key = response_data
        shared_secret = create_shared_secret(client_data.private_key, public_key)
        client_data.contacts[recipient_phone] = shared_secret
    shared_secret = client_data.contacts[recipient_phone]    
    print(f"Successfully created/loaded a shared secret: {shared_secret}")
    aes_key = create_AES_key()
    encrypted_aes_key = aes_ecb_encrypt(aes_key["key"], shared_secret)
    print("Successfully encrypted the aes key with shared secret")
    decrypted_aes_key = aes_ecb_decrypt(encrypted_aes_key, shared_secret)
    print(f"Successfully decrypted aes key: {decrypted_aes_key}")

        
def main():
    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
            logger.info(f"Connected to server at {HOST}:{PORT}")

            if client_data.is_signed_up:
                logger.info("Signing in...")
                # TODO: JASON - Work on sign in function
            else:
                logger.info("Signing up...")
                sign_up(client_socket)
                request = input("Would you like to send a new message? Y/n")
                while request.lower() != "n":
                    recipient_phone = input("Enter recipient's phone:\t")
                    if len(recipient_phone) != 10 or not recipient_phone.isdigit():
                        print("Invalid phone number")
                    else:
                        message = input("Enter your message:\t")     
                        send_msg(client_socket, recipient_phone, message) 
                    request = input("Would you like to send a new message? Y/n")
    
        except ConnectionClosed as e:
            logger.warning(f"Connection with server unexpectedly closed: {e}")
        except KeyboardInterrupt:
            logger.info("\nClient shutting down.")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
        finally:
            client_data.save_data()
            logger.info("Connection closed.")

if __name__ == "__main__":
    logger.debug("Main function called")
    main()
