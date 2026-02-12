import socket
import ssl
import ipaddress
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs (allowlist)
ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Replace with your allowed domains
ALLOWED_IPS = ["127.0.0.1", "192.168.1.1"]  # Replace with your allowed IPs

# Maximum number of connections
MAX_CONNECTIONS = 10

# Keep track of the number of active connections
active_connections = 0

def is_valid_ip(ip_address):
    """
    Validate if the provided IP address is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_allowed(host):
    """
    Check if the host is in the allowlist (either domain or IP).
    """
    if host in ALLOWED_DOMAINS:
        return True
    if is_valid_ip(host) and host in ALLOWED_IPS:
        return True
    try:
        # Attempt to resolve the hostname to an IP address and check if it's allowed
        ip_address = socket.gethostbyname(host)
        if ip_address in ALLOWED_IPS:
            return True
    except socket.gaierror:
        logging.warning(f"Could not resolve hostname: {host}")
        return False
    return False

def connect(host, port):
    """
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.
    """
    global active_connections

    # Validate host and port
    if not isinstance(host, str):
        raise TypeError("Host must be a string.")
    if not isinstance(port, int):
        raise TypeError("Port must be an integer.")
    if not (0 < port < 65536):
        raise ValueError("Port must be between 1 and 65535.")

    # Check if the host is allowed
    if not is_allowed(host):
        logging.warning(f"Connection to host {host} is not allowed.")
        raise ValueError(f"Connection to host {host} is not allowed.")

    # Limit the number of connections
    if active_connections >= MAX_CONNECTIONS:
        logging.warning("Maximum number of connections reached.")
        raise ConnectionError("Maximum number of connections reached.")

    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create an SSL context
        context = ssl.create_default_context()

        # Validate the server's certificate
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()  # Load default CA certificates

        # Wrap the socket with SSL
        secure_socket = context.wrap_socket(sock, server_hostname=host)

        # Connect to the server
        secure_socket.connect((host, port))

        # Increment the number of active connections
        active_connections += 1
        logging.info(f"Connected to {host}:{port} successfully.")

        return secure_socket

    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        raise
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise

def close_connection(sock):
    """
    Closes the socket connection and decrements the active connection count.
    """
    global active_connections
    try:
        sock.close()
        active_connections -= 1
        logging.info("Connection closed successfully.")
    except Exception as e:
        logging.error(f"Error closing connection: {e}")

if __name__ == '__main__':
    try:
        # Example usage:
        s = connect("example.com", 443)  # Replace with your desired host and port
        # Perform operations with the socket (e.g., send/receive data)
        s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = s.recv(1024)
        print(data.decode())
        close_connection(s)

    except Exception as e:
        logging.error(f"An error occurred: {e}")

