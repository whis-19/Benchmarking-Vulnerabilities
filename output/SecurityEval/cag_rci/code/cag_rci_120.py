import re
import urllib.parse
import json
import logging
import socket
import ssl
import tldextract
from idna import idna
from jsonschema import validate, ValidationError  # pip install jsonschema
import time  # For rate limiting

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from file
def load_config(filepath="config.json"):
    try:
        with open(filepath, "r") as f:
            config = json.load(f)
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {filepath}")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in configuration file: {filepath}")
        return {}

config = load_config()
ALLOWED_DOMAINS = config.get("allowed_domains", ["example.com"])  # Default if not found
ALLOWED_IPS = config.get("allowed_ips", ["127.0.0.1"])

# HTTPS port
HTTPS_PORT = 443

# JSON Schema for UDP packet validation
UDP_PACKET_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "format": "uri"},
        "data": {"type": "integer"}  # Example: Expecting an integer
    },
    "required": ["url", "data"]
}

# Rate limiting parameters
REQUEST_LIMIT = 10  # Maximum requests per minute
REQUEST_WINDOW = 60  # Time window in seconds
request_counts = {}  # {ip_address: [timestamp1, timestamp2, ...]}

def is_rate_limited(ip_address):
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = []

    # Remove old requests
    request_counts[ip_address] = [ts for ts in request_counts[ip_address] if now - ts < REQUEST_WINDOW]

    if len(request_counts[ip_address]) >= REQUEST_LIMIT:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return True

    request_counts[ip_address].append(now)
    return False


def is_valid_url(url):
    """
    Validates a URL to prevent malicious URLs.  More robust checks.
    """
    try:
        result = urllib.parse.urlparse(url)
        if not all([result.scheme, result.netloc, result.path]):
            return False
        if result.scheme not in ['http', 'https']:
            return False

        # Robust netloc validation using regex
        netloc_regex = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"  # More specific hostname regex
        if not re.match(netloc_regex, result.netloc):
            return False

        # Path validation (example: prevent directory traversal)
        if ".." in result.path:
            return False

        # Length limits
        if len(result.netloc) > 255 or len(result.path) > 1024:
            return False

        return True
    except:
        return False

def is_allowed_domain(domain):
    """
    Checks if a domain is in the allowlist, using the registered domain.
    """
    try:
        extracted = tldextract.extract(domain)
        registered_domain = ".".join(extracted[1:])  # Combine domain and suffix
        return registered_domain in ALLOWED_DOMAINS
    except Exception as e:
        logging.error(f"Error extracting domain: {e}")
        return False

def is_allowed_ip(ip_address):
    """
    Checks if an IP address is in the allowlist.
    """
    return ip_address in ALLOWED_IPS

def sanitize_data(data):
    """
    Sanitizes data to prevent injection attacks.  Context-aware sanitization.
    """
    # Example:  If data_payload is expected to be an integer, this function is not needed.
    # If data_payload is expected to be a string with a maximum length:
    if not isinstance(data, str) or len(data) > 256:
        logging.warning(f"Invalid data payload: Expected string (max 256 chars), got {data}")
        return None
    # Example: Allowlist of characters
    allowed_chars = re.compile(r"^[a-zA-Z0-9\s]+$")  # Alphanumeric and spaces
    if not allowed_chars.match(data):
        logging.warning(f"Invalid characters in data: {data}")
        return None
    return data

def parseUDPpacket(data):
    """
    Parses the UDP packet data, expecting a JSON payload.
    """
    try:
        packet = json.loads(data.decode('utf-8'))

        # Validate against JSON schema
        try:
            validate(instance=packet, schema=UDP_PACKET_SCHEMA)
        except ValidationError as e:
            logging.warning(f"Invalid UDP packet format: JSON schema validation failed: {e}")
            return None

        url = packet.get('url')
        data_payload = packet.get('data')

        # Validate the URL
        if not is_valid_url(url):
            logging.warning(f"Invalid URL in UDP packet: {url}")
            return None

        # Extract domain for allowlist check
        domain = urllib.parse.urlparse(url).netloc
        try:
            domain = idna.decode(domain)  # Prevent IDN homograph attacks
        except Exception as e:
            logging.warning(f"Error decoding domain: {e}")
            return None

        if not is_allowed_domain(domain):
            logging.warning(f"Domain not allowed: {domain}")
            return None

        # Sanitize the data payload (replace with context-aware sanitization)
        # Example: If data_payload is expected to be an integer:
        sanitized_data = data_payload # No need to sanitize if it's already validated as an integer by the schema

        # OR, if data_payload is expected to be a string with a maximum length:
        # sanitized_data = sanitize_data(data_payload)
        # if sanitized_data is None:
        #     return None

        return url, str(sanitized_data) # Convert back to string for consistency

    except json.JSONDecodeError as e:
        logging.warning(f"Invalid JSON in UDP packet: {e}")
        return None
    except Exception as e:
        logging.error(f"Error parsing UDP packet: {e}")
        return None

def sendResponse(url, data):
    """
    Sends the data to the specified URL using HTTPS.
    """
    secure_sock = None  # Initialize to None for proper cleanup
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else "/"

        # Resolve hostname to IP address and check against allowlist
        try:
            ip_address = socket.gethostbyname(hostname)
            if not is_allowed_ip(ip_address):
                logging.warning(f"IP address not allowed: {ip_address}")
                return
        except socket.gaierror as e:
            logging.error(f"Could not resolve hostname: {hostname} - {e}")
            return


        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Wrap the socket with SSL/TLS
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = True  # Verify hostname
        context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification
        # Load trusted CA certificates (optional, but recommended)
        # context.load_verify_locations('/path/to/your/ca_bundle.pem') # Replace with your CA bundle path
        context.minimum_version = ssl.TLSVersion.TLSv1_2 # Enforce TLS 1.2 or higher

        secure_sock = context.wrap_socket(sock, server_hostname=hostname)

        # Connect to the server
        secure_sock.connect((hostname, HTTPS_PORT))

        # Construct the HTTPS request
        import urllib.parse
        data_dict = {'data': data}  # Wrap your data in a dictionary
        encoded_data = urllib.parse.urlencode(data_dict)

        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        request += "Content-Type: application/x-www-form-urlencoded\r\n"  # Adjust content type as needed
        request += f"Content-Length: {len(encoded_data)}\r\n"
        request += "Connection: close\r\n\r\n"
        request += encoded_data

        # Send the request
        secure_sock.sendall(request.encode('utf-8'))

        # Receive the response (optional, but good practice)
        response = b""
        while True:
            chunk = secure_sock.recv(4096)
            if not chunk:
                break
            response += chunk

        logging.info(f"Response from {url}: {response.decode('utf-8')}")


    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if secure_sock:  # Check if the socket was created
            try:
                secure_sock.close()
            except Exception as e:
                logging.error(f"Error closing socket: {e}")


def sendData():
    """
    Creates a UDP socket and continuously receives UDP packets, parses them,
    and sends the data to the appropriate requested IP address.
    """
    UDP_IP = "127.0.0.1"  # Listen on all interfaces
    UDP_PORT = 5005

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    logging.info(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
            ip_address = addr[0]  # Extract IP address from the address tuple

            if is_rate_limited(ip_address):
                logging.warning(f"Dropping packet from rate-limited IP: {ip_address}")
                continue  # Skip processing the packet

            logging.info(f"Received message from {addr}: {data}")

            # Parse the UDP packet
            parsed_data = parseUDPpacket(data)

            if parsed_data:
                url, sanitized_data = parsed_data
                # Send the response
                sendResponse(url, sanitized_data)  # No need to encode, it's already a string
            else:
                logging.warning("Failed to parse UDP packet.  Ignoring.")

        except Exception as e:
            logging.error(f"Error receiving or processing UDP packet: {e}")


if __name__ == "__main__":
    sendData()

