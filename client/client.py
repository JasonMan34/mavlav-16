import secrets
import socket

from client_data import client_data
from logger import logger
from protocol import RequestType, ResponseType
from crypto import *
from base64 import b64decode
import struct
import json

class ConnectionClosed(Exception):
    pass
class PhoneDoesNotExist(Exception):
    pass
class BadRequest(Exception):
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

def send_request(client_socket: socket.socket, request_type: RequestType, data: bytes = b''):
    """
    Send a request to the server.

    :param client_socket: The socket connection to the server.
    :param request_type: The type of the request (e.g., SIGN_UP, SIGN_UP_CONFIRM).
    :param data: The data to send with the request (e.g., phone number, confirmation code).
    """
    
    if request_type in {RequestType.INIT_MESSAGING, RequestType.SEND_MESSAGE}:
        signature = sign(data, client_data.private_key_bytes)
        signature_length_bytes = len(signature).to_bytes(1, 'big')
        total_data_length = len(data) + len(signature_length_bytes) + len(signature)
        data_length_bytes = total_data_length.to_bytes(4, 'big')
        request_message = (
            bytes([request_type.value]) +
            data_length_bytes +
            signature_length_bytes +
            data +
            signature
        )
    else:
        data_length_bytes = len(data).to_bytes(4, 'big')
        request_message = bytes([request_type.value]) + data_length_bytes + data

    # Send the request to the server
    logger.debug(f"Sending {request_type.name} request with data: {data}")
    client_socket.sendall(request_message)
    logger.debug("Request sent.")
    return receive_response(client_socket)


def receive_response(client_socket: socket.socket):
    response_type_int = int.from_bytes(client_socket.recv(1), 'big')
    response_type = ResponseType(response_type_int)
    logger.debug(f"Received response type {response_type}")
    
    if response_type == ResponseType.CONNECTION_CLOSED:
        raise ConnectionClosed("Connection closed by server.")
    
    response_length = int.from_bytes(client_socket.recv(4), 'big')
    logger.debug(f"Received response length {response_length}")
    response_data = recv_exact(client_socket, response_length)
    return response_type, response_data

def verify_server_identity(conn: socket.socket) -> None:
    challenge = secrets.token_bytes(32)
    logger.info("Successfully created secret challenge for server.")
    response_type, response_data = send_request(conn, RequestType.VERIFY_SERVER_IDENTITY, challenge)
    if response_type != ResponseType.SERVER_IDENTITY_VERIFICATION:
        print(f"Unexpected response from server when verifying server identity: {response_type.name}. Exiting.")
        exit(1)
        
    try:
        verify_server_signature(challenge, response_data)
    except Exception:
        print(f"Failed to verify server identity. Exiting.")
        exit(1)
    
    logger.info("Successfully verified server identity using ECDSA.")

def sign_up(conn: socket.socket) -> None:
    # Send SIGN_UP request
    response_type, response_data = send_request(conn, RequestType.SIGN_UP, client_data.phone_number.encode())

    if response_type == ResponseType.SIGN_UP_FAILED_PHONE_NUMBER_ALREADY_REGISTERED.value:
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

    while not client_data.is_signed_up:
        confirmation_code = input("Please Enter the confirmation code: ").strip()
        confirmation_data = confirmation_code.encode() + client_data.public_key_bytes
        response_type, response_data = send_request(conn, RequestType.SIGN_UP_CONFIRM, confirmation_data)

        if response_type == ResponseType.SIGN_UP_SUCCESS:
            client_data.is_signed_up = True
            client_data.save_data()
            print("Sign-up successful!")
        elif response_type == ResponseType.SIGN_UP_FAILED_WRONG_DIGITS:
            print("Wrong confirmation code entered. Please try again.")
        elif response_type == ResponseType.SIGN_UP_FAILED_TOO_MANY_ATTEMPTS:
            print("Too many failed sign-up attempts. Exiting.")
            exit(1)
        else:
            logger.error(f"Unexpected response from server: {response_type.name}")
            exit(1)

def sign_in(conn: socket.socket):
    # Send SIGN_IN request
    response_type, response_data = send_request(conn, RequestType.SIGN_IN, client_data.phone_number.encode())

    if response_type != ResponseType.SIGN_IN_STARTED:
        logger.error(f"Unexpected response from server: {response_type.name}")
        exit(1)

    # Handle challenge
    challenge = response_data
    logger.info("Successfully received sign-in challenge from server")
    signature = sign(challenge, client_data.private_key_bytes)
    logger.info("Successfully signed the challenge using EC private key")
    response_type, response_data = send_request(conn, RequestType.SIGN_IN_CONFIRM, signature)

    if response_type == ResponseType.SIGN_IN_SUCCESS:
        logger.info("Sign-in successful!")
    else:
        logger.error("Sign-in failed. Exiting.")
        exit(1)


def init_messaging(conn: socket.socket, recipient_phone: str):
    response_type, response_data = send_request(conn, RequestType.INIT_MESSAGING, recipient_phone.encode())
    if response_type == ResponseType.RECIPIENT_PHONE_NOT_EXIST:
        raise PhoneDoesNotExist()
    if response_type != ResponseType.SENDING_REQUESTED_PUB_KEY:
        logger.warning(f"Unexpected response from server: {response_type.name}")
        raise BadRequest()

    logger.info(f"Successfully received public key of {recipient_phone}")
    return response_data

def get_and_create_crypto_utils(conn: socket.socket, recipient_phone: str):
    public_key_bytes = init_messaging(conn, recipient_phone)
    shared_secret = create_shared_secret(client_data.private_key_bytes, public_key_bytes)
    logger.info("Successfully created a shared secret")
    aes_key, iv = create_AES_key()
    logger.info("Successfully created AES key")
    client_data.contacts[recipient_phone] = (shared_secret, aes_key, iv)

def send_msg(conn: socket.socket, recipient_phone: str, message: str):
    if recipient_phone in client_data.contacts:
        logger.info(f"You have {recipient_phone} set and ready for messaging!")
    else:
        logger.info(f"Initiating end-to-end encryption with {recipient_phone}...")
        get_and_create_crypto_utils(conn, recipient_phone)

    shared_secret, aes_key, iv = client_data.contacts[recipient_phone]
    logger.info("Successfully dumped shared secret, AES key and iv")
    encrypted_aes_key = aes_ecb_encrypt(aes_key, shared_secret)
    logger.info("Successfully encrypted AES key for transmission (encrypted using shared secret in ECB mode)")
    encrypted_msg = aes_cbc_encrypt(message.encode(), aes_key, iv)
    logger.info(f"Successfully encrypted message to send to {recipient_phone} (encrypted using AES key in CBC mode)")

    response_type, response_data = send_request(conn, RequestType.SEND_MESSAGE, struct.pack(
        f'>10s48s16s{len(encrypted_msg)}s',
        recipient_phone.encode(),
        encrypted_aes_key,
        iv,
        encrypted_msg
    ))

    if response_type != ResponseType.MESSAGE_SENT:
        print("Failed to send message to", recipient_phone)
        logger.error(f"Failed to send message to {recipient_phone}. Response type: {response_type}")
    else:
        print(f"Successfully sent message to {recipient_phone}")


def receive_incoming_messages(conn: socket.socket):
    response_type, response_data = send_request(conn, RequestType.RECEIVE_MESSAGES)
    messages = json.loads(response_data.decode())
    if not messages:
        print("\nNo messages.")
        return

    for sender in messages:
        if sender not in client_data.contacts:
            get_and_create_crypto_utils(conn, sender)

        shared_secret, aes_key, iv = client_data.contacts[sender]
        print(f"\nYou've received the following messages from {sender}:")
        for msg in messages[sender]:
            decoded_msg = b64decode(msg)
            encrypted_aes, iv, encrypted_msg = struct.unpack(
                f'>48s16s{len(decoded_msg)-48-16}s',
                decoded_msg
            )
            aes_key = aes_ecb_decrypt(encrypted_aes, shared_secret)
            decrypted_msg = aes_cbc_decrypt(encrypted_msg, aes_key, iv)
            print(decrypted_msg.decode())



def get_user_action():
    return input("""
What would you like to do?
0 - Send message
1 - Receive all messages
2 - Quit
""").strip()

def user_action_loop(client_socket: socket.socket):
    action = get_user_action()
    while action != "2":
        try:
            if action == "0":
                recipient_phone = input("Enter recipient's phone: ")
                if len(recipient_phone) != 10 or not recipient_phone.isdigit():
                    print("Invalid phone number")
                else:
                    message = input("Enter your message: ")
                    send_msg(client_socket, recipient_phone, message)
            elif action == "1":
                receive_incoming_messages(client_socket)
            else:
                print("Invalid action.")

            action = get_user_action()
        except PhoneDoesNotExist:
            print("That phone number does not exist on the server")
        except BadRequest:
            print("Something went wrong")



def main():
    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
            logger.info(f"Connected to server at {HOST}:{PORT}")
            
            verify_server_identity(client_socket)
            
            if client_data.is_signed_up:
                logger.info("Signing in...")
                sign_in(client_socket)
            else:
                logger.info("Signing up...")
                sign_up(client_socket)

            user_action_loop(client_socket)
        except ConnectionClosed as e:
            print("Connection with server unexpectedly closed.")
            logger.warning(f"Connection with server unexpectedly closed: {e}")
        except KeyboardInterrupt:
            logger.info("\nClient shutting down.")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        finally:
            logger.info("Connection closed.")

if __name__ == "__main__":
    logger.debug("Main function called")
    main()
