import socket
import ssl
import logging
import re
import hashlib

logging.basicConfig(level=logging.INFO)  # Configure logging

def is_valid_hostname(hostname):
    """
    Validates that the hostname conforms to a basic hostname format.
    This is a simplified check and may need to be adjusted based on specific requirements.
    """
    hostname_regex = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(hostname_regex.match(hostname))


def connect(host, port):
    '''
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.
    '''
    try:
        # Create a TCP socket (IPv4)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Add a 10-second timeout

        # Create an SSL context.  Use TLSv1.2 or higher for security.
        #  TLSv1.3 is preferred if available.  Disable SSLv3, TLSv1, and TLSv1.1.
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2 or higher

        # Wrap the socket with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=host)  # server_hostname is crucial for SNI

        # Connect to the server
        ssl_sock.connect((host, port))

        # Example: Pinning to a specific certificate hash (SHA256) - REMOVE OR REPLACE IN PRODUCTION
        # expected_fingerprint = "YOUR_EXPECTED_CERTIFICATE_SHA256_HASH"  # Replace with the actual hash

        # def verify_certificate_fingerprint(ssl_sock, host, expected_fingerprint):
        #     cert = ssl_sock.getpeercert(binary_form=True)
        #     if not cert:
        #         raise ssl.SSLError("No certificate received from server.")

        #     fingerprint = hashlib.sha256(cert).hexdigest()
        #     if fingerprint != expected_fingerprint:
        #         raise ssl.SSLError(f"Certificate fingerprint mismatch: Expected {expected_fingerprint}, got {fingerprint}")

        # # Verify the certificate fingerprint after connecting
        # verify_certificate_fingerprint(ssl_sock, host, expected_fingerprint)


        return ssl_sock

    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except ConnectionRefusedError as e:
        logging.error(f"Connection refused: {e}")
        return None
    except socket.timeout as e:
        logging.error(f"Connection timed out: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full traceback
        return None


if __name__ == '__main__':
    # Example usage (replace with your desired host and port)
    host = "www.google.com"  # Example host
    port = 443  # Standard HTTPS port

    # Input validation for host and port
    if not isinstance(host, str):
        logging.error("Host must be a string.")
        exit(1)

    if not is_valid_hostname(host):
        logging.error("Invalid hostname format.")
        exit(1)

    try:
        port = int(port)
        if not (0 < port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        logging.error(f"Invalid port: {e}")
        exit(1)


    ssl_socket = connect(host, port)

    if ssl_socket:
        try:
            # Send a simple HTTP request (GET /)
            request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
            ssl_socket.sendall(request)

            # Receive the response (read in chunks)
            response = b""
            max_response_size = 65536  # Example maximum response size
            while True:
                try:
                    chunk = ssl_socket.recv(4096)
                    if not chunk:
                        break  # Connection closed by server
                    response += chunk
                    if len(response) > max_response_size:
                        logging.error("Response exceeds maximum allowed size.")
                        break  # Stop reading if response is too large
                except socket.timeout:
                    logging.warning("Timeout while receiving data.")
                    break
                except Exception as e:
                    logging.exception(f"Error receiving data: {e}")
                    break

            try:
                print(response.decode(errors='ignore'))  # Handle potential decoding errors
            except UnicodeDecodeError:
                logging.error("Could not decode the response.")


        except Exception as e:
            logging.exception(f"Error during communication: {e}")
        finally:
            ssl_socket.close()
    else:
        logging.error("Failed to establish SSL connection.")

