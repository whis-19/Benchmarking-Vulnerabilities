import time
import hashlib
import hmac
import os
import secrets
import json
import logging

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for message integrity
SECRET_KEY = secrets.token_bytes(32)  # Generate a strong, random key
ALGORITHM = 'sha256'
ENCODING = 'utf-8'  # Explicitly define encoding

def generate_timestamp():
    """
    Generates a timestamp with millisecond precision.
    """
    return time.time()

def create_message(data):
    """
    Creates a secure message with timestamp and HMAC.

    Args:
        data: The data to be included in the message (must be serializable).

    Returns:
        A dictionary containing the timestamp, data, and HMAC.
    """
    timestamp = generate_timestamp()
    message = {
        'timestamp': timestamp,
        'data': data
    }
    message_json = json.dumps(message, ensure_ascii=False).encode(ENCODING)  # Ensure consistent encoding
    hmac_value = generate_hmac(message_json)
    return {
        'timestamp': timestamp,
        'data': data,
        'hmac': hmac_value.hex()
    }

def verify_message(message):
    """
    Verifies the integrity of a message using HMAC.

    Args:
        message: A dictionary containing the timestamp, data, and HMAC.

    Returns:
        True if the message is valid, False otherwise.
    """
    try:
        timestamp = message['timestamp']
        data = message['data']
        hmac_received = message['hmac']

        # Reconstruct the message used for HMAC generation
        message_reconstructed = {
            'timestamp': timestamp,
            'data': data
        }
        message_json = json.dumps(message_reconstructed, ensure_ascii=False).encode(ENCODING)
        hmac_calculated = generate_hmac(message_json)

        # Compare the received HMAC with the calculated HMAC
        return hmac.compare_digest(hmac_calculated.hex(), hmac_received)

    except (KeyError, TypeError, ValueError) as e:
        logging.error(f"Error verifying message: {e}")
        return False

def generate_hmac(message):
    """
    Generates an HMAC for the given message.

    Args:
        message: The message to generate the HMAC for (bytes).

    Returns:
        The HMAC object.
    """
    return hmac.new(SECRET_KEY, message, hashlib.sha256).digest()


def currentTime():
    '''
    Print the current processor time in seconds, securely.
    '''
    current_time = time.process_time()
    message = create_message({'time': current_time})
    print(f"Current processor time (secure): {message}")
    logging.info(f"Current processor time requested: {message}") # Log the request

    # Example of verifying the message (for demonstration)
    if verify_message(message):
        logging.info("Message integrity verified.")
    else:
        logging.warning("Message integrity verification failed!")


# Example usage (demonstrates message creation and verification)
if __name__ == "__main__":
    currentTime()

    # Simulate receiving a message
    received_message = {
        'timestamp': 1678886400.0,  # Example timestamp
        'data': {'example': 'data'},
        'hmac': 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'  # Example HMAC (replace with a real one)
    }

    # Verify the received message
    is_valid = verify_message(received_message)
    print(f"Received message is valid: {is_valid}")

