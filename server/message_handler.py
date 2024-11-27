from logger import logger
from shared.protocol import ResponseType


class MessageHandler:
    def __init__(self) -> None:
        pass

    def handle_message(self, data: bytes, state: dict) -> bytes:
        """
        This method processes the incoming message and returns a response.

        :param data: The data received from the client
        :param state: The state of the client 
        :return: The response message to send back to the client.
        """
        if len(data) < 1:
            return b"Invalid message format"

        message_type = data[0]  # 1 byte for message type
        message_content = data[1:]  # The rest is the message content

        logger.info(f"Received message {message_type} from {state['addr']}")

        # Handle the message based on the message type.
        if message_type == 1:
            response = self.handle_type_1(message_content)
        else:
            logger.warning(f"Received unknown message type {message_type} from {state['addr']}")
            response = self.handle_unknown_type(message_content)

        return response

    def handle_type_1(self, content: bytes) -> bytes:
        return self.generate_response(18, "Hello from the server".encode())

    def handle_unknown_type(self, content: bytes) -> bytes:
        return self.generate_response(ResponseType.UNKNOWN_REQUEST_TYPE)

    
    @staticmethod
    def generate_response(status: int, extra_data: bytes = b"") -> bytes:
        """
        This method generates a response message with the given status and extra data.

        :param status: The 1 byte status of the response
        :param extra_data: Extra data to send after the status byte
        :return: The binary message to send
        """
        return bytes([status]) + extra_data
