import socket
import ssl
import ipaddress
from urllib.parse import urlparse

# Constants for security
ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Example, replace with your allowed domains
MAX_CONNECTIONS = 10  # Limit the number of connections
CONNECTION_COUNT = 0  # Track the number of connections

def is_valid_ip_address(host):
    """
    Validates if the provided host is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_allowed_domain(host):
    """
    Checks if the provided host is in the allowlist of allowed domains.
    """
    return host in ALLOWED_DOMAINS

def is_valid_url(url):
    """
    Validates the URL to prevent injection attacks.  Checks scheme, netloc, and path.
    """
    try:
        result = urlparse(url)
        return all([result.scheme == 'https', result.netloc, result.path != ''])
    except:
        return False

def connect(host, port):
    """
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.
    """
    global CONNECTION_COUNT

    # Input validation and sanitization
    if not isinstance(host, str):
        raise TypeError("Host must be a string.")
    if not isinstance(port, int):
        raise TypeError("Port must be an integer.")
    if not (0 < port < 65536):
        raise ValueError("Port must be between 1 and 65535.")

    # Security checks:  Validate host against allowlist or IP address
    if not (is_valid_ip_address(host) or is_allowed_domain(host)):
        raise ValueError("Host is not allowed.  Must be a valid IP address or in the allowlist.")

    # Limit the number of connections
    if CONNECTION_COUNT >= MAX_CONNECTIONS:
        raise ConnectionError("Maximum number of connections reached.")

    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create an SSL context
        context = ssl.create_default_context()

        # Enforce certificate validation
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()  # Load default CA certificates

        # Wrap the socket with SSL
        secure_sock = context.wrap_socket(sock, server_hostname=host)

        # Connect to the server
        secure_sock.connect((host, port))

        CONNECTION_COUNT += 1
        return secure_sock

    except socket.gaierror as e:
        print(f"Error resolving hostname: {e}")
        raise
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise

def close_connection(sock):
    """
    Closes a socket connection and decrements the connection count.
    """
    global CONNECTION_COUNT
    try:
        sock.close()
        CONNECTION_COUNT -= 1
    except Exception as e:
        print(f"Error closing socket: {e}")

if __name__ == '__main__':
    try:
        # Example usage (replace with your actual host and port)
        host = "example.com"  # Replace with a valid, allowed domain
        port = 443

        # Example of URL validation
        url = "https://example.com/api/data"
        if is_valid_url(url):
            print(f"URL {url} is valid.")
        else:
            print(f"URL {url} is invalid.")

        secure_socket = connect(host, port)
        print(f"Successfully connected to {host}:{port}")

        # Perform some operations with the socket (e.g., send/receive data)
        # ...

        close_connection(secure_socket)
        print("Connection closed.")

    except ValueError as e:
        print(f"Validation Error: {e}")
    except ConnectionError as e:
        print(f"Connection Limit Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

