import random
import secrets

from logger import logger
from protocol import RequestType, ResponseType
from client_state import ClientState
from db import *
import json 
from base64 import b64encode
from crypto import load_public_key, sign, verify_signature

class InvalidSignature(Exception):
    pass

class MessageHandler:
    def __init__(self) -> None:
        pass

    def handle_message(self, request_type: RequestType, data: bytes, state: ClientState) -> bytes:
        """
        This method processes the incoming message and returns a response.

        :param request_type: The request type
        :param data: The data received from the client
        :param state: The state of the client 
        :return: The response message to send back to the client.
        """
        logger.info(f"Received request {request_type.name} from {state.addr}")

        # Handle the message based on the message type.
        try:
            match request_type:
                case RequestType.VERIFY_SERVER_IDENTITY:
                    response = self.handle_verify_server_identity(challenge=data, state=state)
                case RequestType.SIGN_UP:
                    response = self.handle_sign_up(phone_number=data.decode(), state=state)
                case RequestType.SIGN_UP_CONFIRM:
                    digits, public_key_bytes = data[:6].decode(), data[6:]
                    response = self.handle_sign_up_confirm(digits=digits, public_key_bytes=public_key_bytes, state=state)
                case RequestType.SIGN_IN:
                    response = self.handle_sign_in(phone_number=data.decode(), state=state)
                case RequestType.SIGN_IN_CONFIRM:
                    response = self.handle_sign_in_confirm(signature=data, state=state)
                case RequestType.INIT_MESSAGING:
                    data = self.verify_signature_for_message(data, state)
                    response = self.handle_init_messaging(recipient_phone_number=data.decode(), state=state)
                case RequestType.SEND_MESSAGE:
                    data = self.verify_signature_for_message(data, state)
                    response = self.handle_transmit_msg(recipient_phone_number=data[:10].decode(), msg_to_transmit=data[10:], state=state)  
                case RequestType.RECEIVE_MESSAGES:
                    response = self.handle_recv_msgs(state=state)
                case _:
                    response = self.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)
        except InvalidSignature:
            response = self.generate_response(ResponseType.INVALID_SIGNATURE)

        return response

    def handle_verify_server_identity(self, challenge: bytes, state: ClientState) -> bytes:
        state.allowed_requests = [RequestType.SIGN_UP, RequestType.SIGN_IN]
        signature = sign(challenge)
        return self.generate_response(ResponseType.SERVER_IDENTITY_VERIFICATION, signature)

    def verify_signature_for_message(self, data: bytes, state: ClientState):
        signature_length = int.from_bytes(data[:1], 'big')
        message_data = data[1:len(data) - signature_length]
        signature = data[len(data) - signature_length:]
        try:
            verify_signature(message_data, signature, state.public_key)
        except Exception as e:
            logger.debug(f"Client {state.addr} sent invalid signature: {e}")
            raise InvalidSignature

        return message_data

    def handle_sign_up(self, phone_number: str, state: ClientState) -> bytes:
        if is_client_registered(phone_number):
            return self.generate_response(ResponseType.SIGN_UP_FAILED_PHONE_NUMBER_ALREADY_REGISTERED)

        state.phone_number = phone_number
        state.digits = str(random.SystemRandom().randint(0, 999999)).zfill(6)
        state.allowed_requests = [RequestType.SIGN_UP_CONFIRM]
        return self.generate_response(ResponseType.SIGN_UP_STARTED)

    def handle_sign_up_confirm(self, digits: str, public_key_bytes: bytes, state: ClientState) -> bytes:
        if state.phone_number is None:
            raise Exception("Phone number is not set, but handle_sign_up_confirm was called")
        elif is_client_registered(state.phone_number):
            return self.generate_response(ResponseType.SIGN_UP_FAILED_PHONE_NUMBER_ALREADY_REGISTERED)
        elif state.digits is None:
            raise Exception("Digits are not set, but handle_sign_up_confirm was called")
        elif state.digits != digits:
            state.sign_up_attempts += 1
            if state.sign_up_attempts >= 3:
                return self.generate_response(ResponseType.SIGN_UP_FAILED_TOO_MANY_ATTEMPTS)
            return self.generate_response(ResponseType.SIGN_UP_FAILED_WRONG_DIGITS)
        
        
        try:
            public_key = load_public_key(public_key_bytes) # We do this first to ensure it's a valid key
            state.digits = None
            state.public_key_bytes = public_key_bytes
            state.public_key =  public_key

            register_client(state.phone_number, public_key_bytes)
        except Exception as e:
            logger.warning(f"Invalid public key received from client {state.addr}: {e}")
            return self.generate_response(ResponseType.SIGN_UP_FAILED_INVALID_KEY)

        # client may send messages to other clients now
        state.allowed_requests = [RequestType.INIT_MESSAGING, RequestType.RECEIVE_MESSAGES, RequestType.SEND_MESSAGE]
        return self.generate_response(ResponseType.SIGN_UP_SUCCESS)


    def handle_sign_in(self, phone_number: str, state: ClientState) -> bytes:
        if not is_client_registered(phone_number):
            return self.generate_response(ResponseType.SIGN_IN_FAILED_PHONE_NUMBER_NOT_REGISTERED)

        state.phone_number = phone_number
        challenge = secrets.token_bytes(32)
        state.sign_in_challenge = challenge
        state.allowed_requests = [RequestType.SIGN_IN_CONFIRM]
        return self.generate_response(ResponseType.SIGN_IN_STARTED, challenge)
    
    def handle_sign_in_confirm(self, signature: bytes, state: ClientState) -> bytes:
        if not state.phone_number or not state.sign_in_challenge:
            return self.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)

        public_key_bytes = get_public_key_bytes(state.phone_number)
        if not public_key_bytes:
            return self.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)

        try:
            public_key = load_public_key(public_key_bytes)
            verify_signature(state.sign_in_challenge, signature, public_key)
            state.public_key_bytes = public_key_bytes
            state.public_key = public_key
            state.sign_in_challenge = None
            state.allowed_requests = [RequestType.INIT_MESSAGING, RequestType.RECEIVE_MESSAGES, RequestType.SEND_MESSAGE]
            return self.generate_response(ResponseType.SIGN_IN_SUCCESS)
        except Exception as e:
            logger.debug(f"Client {state.addr} sent invalid signature: {e}")
            raise InvalidSignature

    def handle_init_messaging(self, recipient_phone_number: str, state: ClientState) -> bytes:
        if not is_client_registered(state.phone_number):
            return self.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)
        
        recipient_public_key_bytes = get_public_key_bytes(recipient_phone_number)
        if recipient_public_key_bytes:
            return self.generate_response(ResponseType.SENDING_REQUESTED_PUB_KEY, recipient_public_key_bytes)
        else:
            return self.generate_response(ResponseType.RECIPIENT_PHONE_NOT_EXIST)

    def handle_transmit_msg(self, recipient_phone_number: str, msg_to_transmit: bytes, state: ClientState):
        if not is_client_registered(state.phone_number):
            return self.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)
        
        if recipient_phone_number not in registered_clients:
            return self.generate_response(ResponseType.RECIPIENT_PHONE_NOT_EXIST)
        
        if state.phone_number not in messages[recipient_phone_number]:
            messages[recipient_phone_number][state.phone_number] = []

        messages[recipient_phone_number][state.phone_number].append(b64encode(msg_to_transmit).decode())
    
        return self.generate_response(ResponseType.MESSAGE_SENT)   
        
    def handle_recv_msgs(self, state: ClientState):
        if not is_client_registered(state.phone_number):
            return self.generate_response(ResponseType.REQUEST_TYPE_NOT_ALLOWED)

        client_messages = messages[state.phone_number]
        return self.generate_response(ResponseType.HERE_ARE_YOUR_MESSAGES, json.dumps(client_messages).encode())
    
    @staticmethod
    def generate_response(response_type: ResponseType, data = b"", sign_data = False) -> bytes:

        """
        Generates a response to send back to the client.

        :param response_type: The response type
        :param data: The data to send with the response
        :param sign_data: Whether to sign the response data
        :return: The response as bytes
        """
        if sign_data:
            signature = sign(data)
            extra_data_length = (len(data) + 512).to_bytes(4, 'big')
            return bytes([response_type.value]) + extra_data_length + data + signature
        else:
            extra_data_length = len(data).to_bytes(4, 'big')
            return bytes([response_type.value]) + extra_data_length + data
