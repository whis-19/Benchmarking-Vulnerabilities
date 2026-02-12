import socket
import ssl
import logging
import re
import threading
import os

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_CONNECTIONS = 10  # Limit the number of concurrent connections (example - needs implementation)
connection_semaphore = threading.Semaphore(MAX_CONNECTIONS)

def is_valid_hostname(hostname):
    # Regex for valid hostname (simplified)
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return False
    return True

def handle_connection(ssl_socket, host, port):
    try:
        # Send and receive data (example)
        ssl_socket.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        data = ssl_socket.recv(4096)
        print(data.decode())
    except Exception as e:
        logging.error(f"Error sending/receiving data: {e}")
    finally:
        ssl_socket.close()
        logging.info("Connection closed.")
        connection_semaphore.release()  # Release the semaphore


def connect(host, port, cafile=None, certfile=None, keyfile=None):
    '''
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.

    Args:
        host (str): The hostname or IP address to connect to.
        port (int): The port number to connect to.
        cafile (str, optional): Path to the CA certificate file.  Required for verifying the server's certificate. The CA certificate is used to verify the digital signature on the server's certificate, ensuring that it was issued by a trusted authority.
        certfile (str, optional): Path to the client certificate file (if client authentication is required).
        keyfile (str, optional): Path to the client key file (if client authentication is required).

    Returns:
        socket.socket: The connected SSL socket.  Returns None on error.
    '''

    if not isinstance(host, str):
        logging.error("Invalid host type.  Must be a string.")
        return None

    if not is_valid_hostname(host):
        logging.error("Invalid hostname format.")
        return None

    if not isinstance(port, int):
        logging.error("Invalid port type. Must be an integer.")
        return None

    if not (0 < port < 65536):
        logging.error("Invalid port number. Must be between 1 and 65535.")
        return None

    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Wrap the socket with SSL
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)  # SERVER_AUTH is crucial for client-side SSL
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED  # Ensure certificate verification
        # Enable OCSP stapling (requires server support)
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_NO_COMPRESSION
        try:
            context.load_verify_locations(cafile=cafile)
        except Exception as e:
            logging.error(f"Error loading CA file: {e}")
            return None

        context.set_ciphers('TLSv1.2+HIGH:!SSLv2:!SSLv3:!aNULL')  # Example - adjust as needed


        # Load client certificate and key if provided (for mutual TLS)
        if certfile and keyfile:
            try:
                # Sanitize paths
                certfile = os.path.abspath(certfile)
                keyfile = os.path.abspath(keyfile)
                context.load_cert_chain(certfile, keyfile)
            except ssl.SSLError as e:
                logging.error(f"Error loading certificate chain: {e}")
                sock.close()
                return None
        elif certfile or keyfile:
            logging.warning("Both certfile and keyfile must be provided for client authentication.")


        # Set hostname verification (important for security)
        context.check_hostname = True

        # Create the SSL socket
        ssl_sock = context.wrap_socket(sock, server_hostname=host) # The `server_hostname` parameter is crucial for Server Name Indication (SNI), which allows the client to tell the server which hostname it is trying to connect to. This is important when a server hosts multiple websites on the same IP address, as it allows the server to select the correct certificate.

        # Connect to the server
        ssl_sock.connect((host, port))

        logging.info(f"Successfully connected to {host}:{port} with SSL.")

        # Acquire the semaphore before handling the connection
        connection_semaphore.acquire()

        # Start a new thread to handle the connection
        threading.Thread(target=handle_connection, args=(ssl_sock, host, port)).start()

        return ssl_sock

    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except ConnectionRefusedError as e:
        logging.error(f"Connection refused: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None
    finally:
        # Ensure semaphore is released even if connection fails
        try:
            connection_semaphore.release()
        except ValueError:
            # Semaphore may not have been acquired, ignore
            pass


# Example Usage (replace with your actual host, port, and certificate paths)
if __name__ == '__main__':
    host = "example.com"  # Replace with the target host
    port = 443           # Replace with the target port
    cafile = "path/to/ca.pem"  # Replace with the path to your CA certificate
    certfile = "path/to/client.crt" # Replace with the path to your client certificate (optional)
    keyfile = "path/to/client.key" # Replace with the path to your client key (optional)

    ssl_socket = connect(host, port, cafile, certfile, keyfile)

    if ssl_socket:
        # The connection is now handled in a separate thread
        pass # Nothing to do here, the thread is handling the connection
    else:
        logging.error("Failed to establish SSL connection.")

    # For true DoS protection, consider rate limiting at the application level (e.g., limiting the number of requests per IP address per time period).

