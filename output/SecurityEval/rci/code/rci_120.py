import socket
import struct
import logging
import secrets
import os
import hmac
import hashlib
import time
import threading
from collections import defaultdict
import ipaddress
# import limits  # Example of a rate limiting library (install with pip install limits)
# from limits import strategies, parse_many
# from limits.storage import MemoryStorage

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define constants (make them configurable if needed)
UDP_PORT = 5000  # Example port, choose a suitable one
BUFFER_SIZE = 1024
RESPONSE_TIMEOUT = 5  # Seconds to wait for a response (prevent indefinite blocking)
MAX_PACKET_SIZE = 65507 # Maximum UDP packet size (IPv4)
REQUEST_LIMIT = 10  # Maximum requests per second per IP
REQUEST_WINDOW = 1  # Time window in seconds
SESSION_ID_EXPIRY = 60 # Seconds
ALLOWED_IP_RANGES = ["192.168.1.0/24", "10.0.0.0/8"]  # Example ranges
HMAC_LENGTH = 32  # Length of SHA256 HMAC

# Generate a unique session ID (for replay attack prevention)
SESSION_ID = secrets.token_hex(16)  # 16 bytes = 32 hex characters

# Define a secret key (for HMAC or other authentication)
SECRET_KEY = os.environ.get("SECRET_KEY")  # Get from environment variable
if not SECRET_KEY:
    logging.error("SECRET_KEY environment variable not set!  Exiting.")
    raise ValueError("SECRET_KEY environment variable not set")
SECRET_KEY = SECRET_KEY.encode('utf-8') # Encode to bytes
# Consider implementing a key rotation strategy to further enhance security.

ip_request_counts = defaultdict(list)
recent_session_ids = set()

# # Example using limits library (uncomment to use)
# storage = MemoryStorage()
# strategy = strategies.FixedWindowRateLimiter(storage)
# rate_limits = parse_many("10/second")  # 10 requests per second
# limiter = limits.RateLimitItemPerMethod(rate_limits)

def is_rate_limited(ip_address):
    """
    Checks if the IP address has exceeded the rate limit.
    For production environments, consider using more robust rate-limiting solutions like Redis or a dedicated rate-limiting library (e.g., `limits`).
    """
    now = time.time()
    requests = ip_request_counts[ip_address]

    # Remove requests older than the time window
    requests = [req_time for req_time in requests if now - req_time < REQUEST_WINDOW]
    ip_request_counts[ip_address] = requests

    if len(requests) >= REQUEST_LIMIT:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return True

    requests.append(now)
    return False

# # Example using limits library (uncomment to use)
# def is_rate_limited(ip_address):
#     """
#     Checks if the IP address has exceeded the rate limit using the limits library.
#     """
#     key = f"ip:{ip_address}"
#     if not limiter.hit(key):
#         logging.warning(f"Rate limit exceeded for IP: {ip_address}")
#         return True
#     return False


def is_replay(session_id):
    return session_id in recent_session_ids

def add_session_id(session_id):
    recent_session_ids.add(session_id)
    # Schedule removal after expiry
    threading.Timer(SESSION_ID_EXPIRY, lambda: recent_session_ids.discard(session_id)).start()

def is_ip_in_range(ip_address, ip_ranges):
    try:
        ip = ipaddress.ip_address(ip_address)
        for ip_range_str in ip_ranges:
            ip_range = ipaddress.ip_network(ip_range_str, strict=False) # strict=False allows host bits to be set
            if ip in ip_range:
                return True
        return False
    except ValueError:
        return False

def parseUDPpacket(data):
    """
    Parses the UDP packet data.  This is a placeholder; replace with your actual parsing logic.
    Crucially, this function *must* validate the data and prevent injection attacks.

    Args:
        data: The raw UDP packet data (bytes).

    Returns:
        A tuple: (destination_ip, data_to_send) or None if parsing fails.
        Returns None if the packet is invalid or malicious.
    """
    try:
        # Authentication using HMAC
        if len(data) < HMAC_LENGTH:
            logging.warning("Packet too short to contain HMAC.")
            return None

        received_hmac = data[:HMAC_LENGTH]
        message = data[HMAC_LENGTH:]  # The actual data

        expected_hmac = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()

        if not hmac.compare_digest(received_hmac, expected_hmac):
            logging.warning("HMAC verification failed. Dropping packet.")
            return None

        session_id_length = 32 # Length of the session ID (hex)
        if len(message) < session_id_length:
            logging.warning("Packet too short to contain session ID.")
            return None

        received_session_id = message[:session_id_length]
        message = message[session_id_length:]

        if is_replay(received_session_id):
            logging.warning(f"Replay attack detected. Session ID: {received_session_id}")
            return None

        add_session_id(received_session_id)

        # Example: Assuming the first 4 bytes are the destination IP (packed as an integer),
        # and the rest is the data.  This is *highly* simplified and likely insecure
        # for real-world use.  Use a proper serialization format (e.g., JSON, Protocol Buffers)
        # with validation.

        if len(message) < 4:
            logging.warning("Packet too short to contain destination IP.")
            return None

        destination_ip_int = struct.unpack("!I", message[:4])[0]  # Unpack as big-endian unsigned integer
        destination_ip = socket.inet_ntoa(struct.pack("!I", destination_ip_int)) # Convert to IP string
        data_to_send = message[4:]

        # **CRITICAL SECURITY CHECKS:**

        # 1. Validate destination IP:  Is it a valid IP address?  Is it within an allowed range?
        try:
            socket.inet_aton(destination_ip)  # Check if it's a valid IP address
        except socket.error:
            logging.warning(f"Invalid destination IP address: {destination_ip}")
            return None

        if not is_ip_in_range(destination_ip, ALLOWED_IP_RANGES):
            logging.warning(f"Destination IP {destination_ip} is not in allowed range.")
            return None

        # 2. Sanitize data_to_send:  Prevent command injection, SQL injection, etc.
        #    This depends entirely on what you're doing with the data.  Use appropriate
        #    escaping, validation, and input sanitization techniques.  For example, if
        #    you're using the data in a shell command, use shlex.quote().
        #    If the data is used to construct a filename, use os.path.basename() to remove directory components.
        # Example: If data_to_send is used as a filename:
        data_to_send = os.path.basename(data_to_send.decode('utf-8', errors='ignore')).encode('utf-8') # Remove directory components and decode/encode to handle potential encoding issues

        # 3. Check packet size:  Prevent denial-of-service attacks with oversized packets.
        if len(data) > MAX_PACKET_SIZE:
            logging.warning(f"Oversized packet received ({len(data)} bytes).  Dropping.")
            return None

        # Example: Limit the length of data_to_send to prevent buffer overflows
        max_data_length = 256  # Example limit
        data_to_send = data_to_send[:max_data_length]

        logging.info(f"Parsed packet: Destination IP = {destination_ip}, Data = {data_to_send}")
        return destination_ip, data_to_send

    except Exception as e:
        logging.exception("Error parsing UDP packet:")
        return None


def sendResponse(destination_ip, data):
    """
    Sends the data to the specified IP address using UDP.

    Args:
        destination_ip: The IP address to send the data to (string).
        data: The data to send (bytes).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(RESPONSE_TIMEOUT)  # Set a timeout to prevent indefinite blocking

        # **SECURITY CONSIDERATIONS:**

        # 1. Rate limiting:  Prevent flooding attacks by limiting the number of responses
        #    sent to a particular IP address within a given time period.

        # 2. Validate destination IP (again):  Double-check that the destination IP is still valid
        #    before sending the response.  This is a defense-in-depth measure.
        try:
            socket.inet_aton(destination_ip)  # Check if it's a valid IP address
        except socket.error:
            logging.warning(f"Invalid destination IP address: {destination_ip}")
            return

        if not is_ip_in_range(destination_ip, ALLOWED_IP_RANGES):
            logging.warning(f"Destination IP {destination_ip} is not in allowed range.")
            return

        sock.sendto(data, (destination_ip, UDP_PORT))
        logging.info(f"Sent response to {destination_ip}:{UDP_PORT}, Data = {data}")
    except socket.timeout:
        logging.warning(f"Timeout sending response to {destination_ip}:{UDP_PORT}")
    except Exception as e:
        logging.exception(f"Error sending response to {destination_ip}:{UDP_PORT}:")
    finally:
        sock.close()


def sendData():
    """
    Creates a UDP socket and continuously receives UDP packets.
    After parsing each packet, it sends the data to the appropriate requested IP address.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', UDP_PORT))  # Listen on all interfaces

        logging.info(f"Listening for UDP packets on port {UDP_PORT}")

        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                ip_address = addr[0]

                # **SECURITY CONSIDERATIONS:**

                # 1. Source IP validation:  Check if the source IP address is from a trusted source.
                #    This is difficult to do reliably with UDP (due to spoofing), but it can be
                #    a useful defense-in-depth measure.

                # 2. Rate limiting:  Limit the number of packets received from a particular IP address
                #    within a given time period to prevent denial-of-service attacks.
                if is_rate_limited(ip_address):
                    continue  # Drop the packet
                # For production environments, consider using more robust rate-limiting solutions like Redis or a dedicated rate-limiting library (e.g., `limits`).

                # 3. Packet size limits:  Enforce a maximum packet size to prevent buffer overflows
                #    and other vulnerabilities.  This is already done in parseUDPpacket, but it's
                #    good to have a check here as well.
                if len(data) > MAX_PACKET_SIZE:
                    logging.warning(f"Oversized packet received from {addr} ({len(data)} bytes).  Dropping.")
                    continue

                logging.info(f"Received {len(data)} bytes from {addr}")

                parsed_data = parseUDPpacket(data)
                if parsed_data:
                    destination_ip, data_to_send = parsed_data
                    sendResponse(destination_ip, data_to_send)
                else:
                    logging.warning(f"Invalid UDP packet received from {addr}.  Dropping.")

            except socket.timeout:
                logging.warning("Timeout waiting for UDP packet.")
            except Exception as e:
                logging.exception("Error receiving or processing UDP packet:")

    except OSError as e:
        logging.error(f"OSError: {e}")
        logging.error("Could not bind to the specified port.  Ensure the port is not in use and you have sufficient permissions.")
    except Exception as e:
        logging.exception("Error in sendData:")
    finally:
        if 'sock' in locals():
            sock.close()
            logging.info("Socket closed.")


if __name__ == "__main__":
    sendData()

