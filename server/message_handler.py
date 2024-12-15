import random
from logger import logger
from protocol import RequestType, ResponseType
from client_state import ClientState
from db import is_client_signed_up, registered_clients


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
        if request_type == RequestType.SIGN_UP:
            response = self.handle_sign_up(phone_number=data.decode(), state=state)
        if request_type == RequestType.SIGN_UP_CONFIRM:
            digits, public_key = data[:6].decode(), data[6:]
            response = self.handle_sign_up_confirm(digits=digits, public_key=public_key, state=state)

        return response

    def handle_sign_up(self, phone_number: str, state: ClientState) -> bytes:
        if is_client_signed_up(phone_number):
            return self.generate_response(ResponseType.PHONE_NUMBER_ALREADY_REGISTERED)

        state.phone_number = phone_number
        state.digits = str(random.randint(0, 999999)).zfill(6)
        state.allowed_requests = [RequestType.SIGN_UP_CONFIRM]
        return self.generate_response(ResponseType.SIGN_UP_STARTED)

    def handle_sign_up_confirm(self, digits: str, public_key: bytes, state: ClientState) -> bytes:
        if state.phone_number is None:
            raise Exception("Phone number is not set, but handle_sign_up_confirm was called")
        elif is_client_signed_up(state.phone_number):
            return self.generate_response(ResponseType.PHONE_NUMBER_ALREADY_REGISTERED)
        elif state.digits is None:
            raise Exception("Digits are not set, but handle_sign_up_confirm was called")
        elif state.digits != digits:
            return self.generate_response(ResponseType.SIGN_UP_WRONG_DIGITS)
        
        state.digits = None
        state.public_key = public_key
        state.allowed_requests = []

        return self.generate_response(ResponseType.SIGN_UP_SUCCESS)

    
    @staticmethod
    def generate_response(response_type: ResponseType, extra_data: bytes = b"") -> bytes:
        """
        This method generates a response message with the given status and extra data.

        :param response_type: The response type
        :param extra_data: Extra data to send after the response type
        :return: The binary message to send
        """
        extra_data_length = len(extra_data).to_bytes(4, 'big')
        return bytes([response_type.value]) + extra_data_length + extra_data
