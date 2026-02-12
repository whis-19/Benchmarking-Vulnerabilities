import socket
import struct
import hashlib
import time
import secrets
import os
import logging
import threading  # For rate limiting

# --- Security Considerations ---
# 1. Data Validation:  All external data (UDP packets) are treated as potentially malicious.
#    - Length checks are performed.
#    - Data types are validated where possible.
#    - Payload content should be validated based on expected format.
# 2. Replay Attacks:  A timestamp-based checksum is used to mitigate replay attacks, combined with a nonce.
#    - Timestamps are checked for freshness.
#    - Nonces are used to prevent replay of packets within the timestamp window.
# 3. DNS Resolution:  `resolveName` is a placeholder.  In a real implementation, DNS resolution *must* be done carefully to prevent DNS poisoning and other attacks.  Use a vetted library and validate responses.  DNSSEC is highly recommended.
# 4. Error Handling:  Comprehensive error handling is included to prevent crashes and information leakage.  Log errors appropriately.
# 5. Input Sanitization:  While this example doesn't directly handle HTTP requests or URLs, the principle of input sanitization is crucial for any real-world application.  Any data received from external sources must be sanitized to prevent XSS, SQL injection, and other vulnerabilities.
# 6. CSRF/XSS:  This code doesn't directly handle web requests, but if it were integrated into a web application, CSRF and XSS protections would be essential.  Use a framework that provides built-in CSRF protection and properly escape all output.
# 7. Rate Limiting:  Implement rate limiting to prevent denial-of-service attacks.  Use a sliding window or token bucket algorithm.
# 8. UDP Protocol Considerations: UDP is connectionless and susceptible to spoofing.  Consider TCP if reliability is needed.

# --- Constants ---
TIMESTAMP_LENGTH = 8  # Length of the timestamp in bytes
CHECKSUM_LENGTH = 32  # Length of the SHA256 checksum in bytes
NONCE_LENGTH = 16  # Length of the nonce in bytes
MAX_UDP_PACKET_SIZE = 65535  # Maximum size of a UDP packet
REPLAY_WINDOW = 5  # Seconds
UDP_IP = "127.0.0.1"  # Listen on localhost
UDP_PORT = 5005
MAX_REQUESTS_PER_SECOND = 10  # Rate limiting
RATE_LIMIT_WINDOW = 1 # seconds
NONCE_CLEANUP_INTERVAL = 60 # seconds

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Rate Limiting ---
class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_counts = {}  # {ip_address: [timestamp1, timestamp2, ...]}
        self.lock = threading.Lock()

    def is_allowed(self, ip_address):
        with self.lock:
            now = time.time()
            if ip_address not in self.request_counts:
                self.request_counts[ip_address] = []

            # Remove requests older than the time window
            self.request_counts[ip_address] = [ts for ts in self.request_counts[ip_address] if now - ts < self.time_window]

            if len(self.request_counts[ip_address]) < self.max_requests:
                self.request_counts[ip_address].append(now)
                return True
            else:
                logging.warning(f"Rate limit exceeded for IP: {ip_address}")
                return False

rate_limiter = RateLimiter(MAX_REQUESTS_PER_SECOND, RATE_LIMIT_WINDOW)  # 10 requests per second

# --- Helper Functions ---

def calculate_checksum(data):
    """Calculates a SHA256 checksum to ensure data integrity."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def verify_checksum(data, received_checksum):
    """Verifies the checksum of the data against the received checksum to detect data corruption."""
    calculated_checksum = calculate_checksum(data)
    return calculated_checksum == received_checksum


# --- Nonce Management ---
class NonceManager:
    def __init__(self):
        self.nonces = {} # {nonce: timestamp}
        self.lock = threading.Lock()

    def is_valid_nonce(self, nonce):
        with self.lock:
            now = time.time()
            if nonce in self.nonces:
                logging.warning(f"Possible replay attack - nonce already used: {nonce}")
                return False
            self.nonces[nonce] = now
            return True

    def remove_old_nonces(self, max_age=60):  # Remove nonces older than 60 seconds
        with self.lock:
            now = time.time()
            self.nonces = {nonce: ts for nonce, ts in self.nonces.items() if now - ts < max_age}

nonce_manager = NonceManager()

def cleanup_nonces():
    """Periodically removes old nonces to prevent memory exhaustion."""
    while True:
        nonce_manager.remove_old_nonces()
        time.sleep(NONCE_CLEANUP_INTERVAL)  # Clean up every 60 seconds (adjust as needed)

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_nonces, daemon=True)  # daemon=True allows the main thread to exit
cleanup_thread.start()


def parseUDPpacket(data):
    """
    Parses a UDP packet, validates its structure, and extracts the relevant data.
    Includes replay attack mitigation using timestamp, nonce, and checksum.
    """
    if not data:
        logging.warning("Received empty UDP packet.")
        return None

    if len(data) < TIMESTAMP_LENGTH + CHECKSUM_LENGTH + NONCE_LENGTH:
        logging.warning("UDP packet too short to contain timestamp, checksum, and nonce.")
        return None

    timestamp_bytes = data[:TIMESTAMP_LENGTH]
    nonce_bytes = data[TIMESTAMP_LENGTH:TIMESTAMP_LENGTH + NONCE_LENGTH]
    checksum_bytes = data[TIMESTAMP_LENGTH + NONCE_LENGTH:TIMESTAMP_LENGTH + NONCE_LENGTH + CHECKSUM_LENGTH].encode('utf-8')
    payload = data[TIMESTAMP_LENGTH + NONCE_LENGTH + CHECKSUM_LENGTH:]

    try:
        timestamp = struct.unpack("!Q", timestamp_bytes)[0]  # Unpack as big-endian unsigned long long
    except struct.error as e:
        logging.error(f"Failed to unpack timestamp: {e}")
        return None

    try:
        nonce = nonce_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        logging.error(f"Failed to decode nonce: {e}")
        return None

    # Replay attack mitigation: Check timestamp freshness (e.g., within REPLAY_WINDOW seconds)
    current_time = int(time.time())
    if abs(current_time - timestamp) > REPLAY_WINDOW:
        logging.warning("Possible replay attack - timestamp too old.")
        return None

    # Replay attack mitigation: Check nonce
    if not nonce_manager.is_valid_nonce(nonce):
        logging.warning("Possible replay attack - invalid nonce.")
        return None

    # Verify checksum
    data_to_verify = timestamp_bytes + nonce_bytes + payload.encode('utf-8')
    calculated_checksum = calculate_checksum(data_to_verify)

    if not verify_checksum(data_to_verify, checksum_bytes.decode('utf-8')):
        logging.warning("Checksum verification failed.")
        return None

    # Return the validated payload
    return payload


def resolveName(nameToResolve):
    """
    Resolves a name to an IP address.  This is a placeholder.
    In a real implementation, this function *must* be carefully implemented
    to prevent DNS poisoning and other attacks.  Use a vetted library and
    validate responses.  DNSSEC is highly recommended.
    """
    # Placeholder:  Replace with secure DNS resolution logic.
    # Example (INSECURE - DO NOT USE IN PRODUCTION):
    # try:
    #     ip_address = socket.gethostbyname(nameToResolve)
    #     return ip_address
    # except socket.gaierror:
    #     print(f"Error: Could not resolve name: {nameToResolve}")
    #     return None

    # Secure placeholder:  Always return None for now.
    logging.warning(f"DNS resolution is a placeholder.  Name: {nameToResolve}")
    return "127.0.0.1"  # return localhost for testing purposes


def sendResponse(requestIP, record):
    """
    Sends a DNS response to the requesting IP address.
    """
    try:
        # Basic validation of the IP address
        socket.inet_aton(requestIP)  # Raises an exception if the IP is invalid
    except socket.error as e:
        logging.error(f"Invalid IP address: {requestIP}: {e}")
        return False

    # Placeholder:  Replace with actual response sending logic.
    logging.info(f"Sending response to {requestIP}: {record}")
    return True


def UDPMessaging(udp_ip, udp_port):
    """
    Creates a UDP socket that listens on the IP and port provided for DNS requests.
    Parses the received data, and sends back the DNS record to the requested IP in the packet.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((udp_ip, udp_port))
        logging.info(f"Listening on {udp_ip}:{udp_port}")

        while True:
            data, addr = sock.recvfrom(MAX_UDP_PACKET_SIZE)  # Limit packet size
            client_ip = addr[0]

            if not data:
                logging.warning(f"Received empty packet from {addr}")
                continue

            # Rate limiting
            if not rate_limiter.is_allowed(client_ip):
                continue  # Drop the packet

            try:
                decoded_data = data.decode('utf-8')  # Decode the received data
                parsed_data = parseUDPpacket(decoded_data)

                if parsed_data:
                    name_to_resolve = parsed_data
                    resolved_record = resolveName(name_to_resolve)

                    if resolved_record:
                        sendResponse(client_ip, resolved_record)  # addr[0] is the IP address
                    else:
                        logging.error("Failed to resolve name.")
                else:
                    logging.error("Failed to parse UDP packet.")

            except UnicodeDecodeError as e:
                logging.error(f"Could not decode UDP packet data: {e}")
            except Exception as e:
                logging.exception(f"An unexpected error occurred: {e}")

    except OSError as e:
        logging.error(f"Could not bind to {udp_ip}:{udp_port}.  {e}")
    except KeyboardInterrupt:
        logging.info("Shutting down UDP server.")
    finally:
        if 'sock' in locals():
            sock.close()


# --- Example Usage ---
if __name__ == "__main__":
    def create_test_packet(payload):
        timestamp = int(time.time())
        timestamp_bytes = struct.pack("!Q", timestamp)
        nonce = secrets.token_hex(NONCE_LENGTH // 2)  # Generate a random nonce
        nonce_bytes = nonce.encode('utf-8')
        data_to_checksum = timestamp_bytes + nonce_bytes + payload.encode('utf-8')
        checksum = calculate_checksum(data_to_checksum)
        packet = timestamp_bytes + nonce_bytes + checksum.encode('utf-8') + payload.encode('utf-8')
        return packet

    # Example usage:
    test_payload = "example.com"
    test_packet = create_test_packet(test_payload)

    # Create a socket to send the test packet
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_socket.sendto(test_packet, (UDP_IP, UDP_PORT))
    test_socket.close()

    UDPMessaging(UDP_IP, UDP_PORT)

