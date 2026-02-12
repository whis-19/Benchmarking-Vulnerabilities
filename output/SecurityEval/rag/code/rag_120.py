import socket
import secrets
import os
import hashlib
import hmac
import time
import struct
from urllib.parse import urlparse

# Constants
UDP_BUFFER_SIZE = 1024
CSRF_TOKEN_LENGTH = 32
HMAC_DIGEST_METHOD = hashlib.sha256
HMAC_KEY = os.urandom(32)  # Generate a strong, random key and store it securely.  DO NOT HARDCODE.

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(CSRF_TOKEN_LENGTH // 2)

def verify_csrf_token(form_token, cookie_token):
    """Verifies that the CSRF token in the form matches the one in the cookie."""
    return hmac.compare_digest(form_token, cookie_token)

def create_hmac(message: bytes, key: bytes = HMAC_KEY, digestmod=HMAC_DIGEST_METHOD) -> bytes:
    """Creates an HMAC for the given message."""
    return hmac.new(key, message, digestmod=digestmod).digest()

def verify_hmac(message: bytes, hmac_value: bytes, key: bytes = HMAC_KEY, digestmod=HMAC_DIGEST_METHOD) -> bool:
    """Verifies the HMAC for the given message."""
    try:
        return hmac.compare_digest(create_hmac(message, key, digestmod), hmac_value)
    except Exception:
        return False  # Handle potential errors during HMAC comparison

def is_valid_url(url):
    """
    Validates the destination URL to prevent open redirects.
    This is a basic example and should be adapted to your specific needs.
    """
    try:
        result = urlparse(url)
        # Check if the scheme is allowed (e.g., http, https)
        if result.scheme not in ('http', 'https'):
            return False

        # Check if the hostname is allowed (e.g., your own domain)
        # This is crucial to prevent redirects to arbitrary domains.
        allowed_hosts = ['yourdomain.com', 'localhost']  # Replace with your allowed domains
        if result.hostname not in allowed_hosts:
            return False

        return True
    except Exception:
        return False

def parseUDPpacket(data):
    """
    Parses the UDP packet data.  This is a placeholder; implement your actual parsing logic here.
    Crucially, validate all data received before using it.

    Args:
        data: The raw UDP packet data (bytes).

    Returns:
        A dictionary containing the parsed data, or None if parsing fails.
    """
    try:
        # Example: Assuming the data is a comma-separated string of key-value pairs
        decoded_data = data.decode('utf-8', 'ignore')  # Decode, handling potential errors
        pairs = decoded_data.split(',')
        parsed_data = {}
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)  # Limit split to 1 to handle values with '='
                # **CRITICAL: Validate key and value before assigning!**
                key = key.strip()
                value = value.strip()

                # Example validation: Check key length and allowed characters
                if not (0 < len(key) <= 32 and key.isalnum()):
                    print(f"Invalid key: {key}")
                    return None  # Or raise an exception

                # Example validation: Check value length and type
                if not (0 < len(value) <= 256):
                    print(f"Invalid value for key {key}: {value}")
                    return None  # Or raise an exception

                parsed_data[key] = value
        return parsed_data
    except Exception as e:
        print(f"Error parsing UDP packet: {e}")
        return None

def sendResponse(data, address, port):
    """
    Sends a response to the specified address and port.

    Args:
        data: The data to send (bytes).
        address: The IP address to send to (string).
        port: The port to send to (integer).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (address, port))
    except Exception as e:
        print(f"Error sending response to {address}:{port}: {e}")

def sendData(udp_listen_address="0.0.0.0", udp_listen_port=5000):
    """
    Creates a UDP socket and continuously receives UDP packets, parses them,
    and sends responses.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((udp_listen_address, udp_listen_port))
            print(f"Listening for UDP packets on {udp_listen_address}:{udp_listen_port}")

            while True:
                data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
                client_address, client_port = addr

                print(f"Received {len(data)} bytes from {client_address}:{client_port}")

                parsed_data = parseUDPpacket(data)

                if parsed_data:
                    # Example: Assuming the parsed data contains 'response_address', 'response_port', and 'response_data'
                    if 'response_address' in parsed_data and 'response_port' in parsed_data and 'response_data' in parsed_data:
                        response_address = parsed_data['response_address']
                        response_port = int(parsed_data['response_port'])  # Convert to integer
                        response_data = parsed_data['response_data'].encode('utf-8') # Encode to bytes

                        # **CRITICAL: Validate the response address before sending!**
                        if is_valid_url(f"http://{response_address}"): # Using http:// for validation only
                            sendResponse(response_data, response_address, response_port)
                        else:
                            print(f"Invalid response address: {response_address}.  Dropping response.")
                    else:
                        print("Missing required fields in parsed data.  Dropping response.")
                else:
                    print("Failed to parse UDP packet.  Dropping response.")

    except Exception as e:
        print(f"Error in sendData: {e}")

if __name__ == '__main__':
    sendData()

