import socket
import ssl
import threading
import logging

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variable to limit the number of connections
MAX_CONNECTIONS = 10  # Adjust as needed
connection_count = 0
connection_lock = threading.Lock()


def connect(host, port, cafile=None, certfile=None, keyfile=None, password=None):
    """
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.

    Args:
        host (str): The hostname or IP address to connect to.
        port (int): The port number to connect to.
        cafile (str, optional): Path to the CA certificate file.  Required for verifying the server's certificate.
        certfile (str, optional): Path to the client certificate file (if client authentication is required).
        keyfile (str, optional): Path to the client key file (if client authentication is required).
        password (str, optional): Password for the keyfile, if encrypted.  Handle securely!

    Returns:
        socket.socket: The connected SSL socket.  Returns None on failure.
    """

    global connection_count
    global connection_lock

    with connection_lock:
        if connection_count >= MAX_CONNECTIONS:
            logging.warning("Maximum number of connections reached.  Connection refused.")
            return None
        connection_count += 1

    try:
        # 1. Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 2. Wrap the socket with SSL
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)  # Server authentication is crucial

        # Optional: Client authentication
        if certfile and keyfile:
            try:
                context.load_cert_chain(certfile, keyfile, password=password) # Password handling is critical
            except ssl.SSLError as e:
                logging.error(f"Error loading certificate chain: {e}")
                with connection_lock:
                    connection_count -= 1
                sock.close()
                return None
            except OSError as e:
                logging.error(f"Error opening certificate files: {e}")
                with connection_lock:
                    connection_count -= 1
                sock.close()
                return None

        # Set hostname verification (important for security)
        context.check_hostname = True
        
        # Set minimum TLS version (TLS 1.2 or higher is recommended)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Wrap the socket
        try:
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
        except OSError as e:
            logging.error(f"Error wrapping socket: {e}")
            with connection_lock:
                connection_count -= 1
            sock.close()
            return None

        # 3. Connect to the server
        try:
            ssl_sock.connect((host, port))
            logging.info(f"Successfully connected to {host}:{port}")
        except socket.gaierror as e:
            logging.error(f"Error resolving hostname: {e}")
            with connection_lock:
                connection_count -= 1
            ssl_sock.close()
            return None
        except ConnectionRefusedError as e:
            logging.error(f"Connection refused: {e}")
            with connection_lock:
                connection_count -= 1
            ssl_sock.close()
            return None
        except ssl.SSLError as e:
            logging.error(f"SSL Error: {e}")
            with connection_lock:
                connection_count -= 1
            ssl_sock.close()
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            with connection_lock:
                connection_count -= 1
            ssl_sock.close()
            return None

        return ssl_sock

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None
    finally:
        pass # No need to decrement connection_count here, it's handled in the error cases and by the caller when the connection is closed.


def close_connection(ssl_sock):
    """
    Closes the SSL socket and decrements the connection count.

    Args:
        ssl_sock (socket.socket): The SSL socket to close.
    """
    global connection_count
    global connection_lock

    try:
        ssl_sock.close()
        logging.info("Connection closed successfully.")
    except Exception as e:
        logging.error(f"Error closing connection: {e}")
    finally:
        with connection_lock:
            connection_count -= 1
            logging.info(f"Connection count decremented. Current count: {connection_count}")


# Example Usage (replace with your actual values)
if __name__ == '__main__':
    host = "www.example.com"  # Replace with the target host
    port = 443  # Standard HTTPS port
    cafile = "path/to/your/ca_certificate.pem"  # Replace with the path to your CA certificate
    certfile = "path/to/your/client_certificate.pem" # Optional client certificate
    keyfile = "path/to/your/client_key.pem" # Optional client key
    password = "your_key_password" # Optional password for the key

    ssl_socket = connect(host, port, cafile=cafile, certfile=certfile, keyfile=keyfile, password=password)

    if ssl_socket:
        try:
            # Send data (example)
            request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
            ssl_socket.sendall(request)

            # Receive data (example)
            response = ssl_socket.recv(4096)
            print(response.decode())

        except Exception as e:
            logging.error(f"Error during communication: {e}")
        finally:
            close_connection(ssl_socket)
    else:
        logging.error("Failed to establish SSL connection.")

