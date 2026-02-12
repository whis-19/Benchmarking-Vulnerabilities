import socket
import threading
import logging
import concurrent.futures
import ssl
import os
import configparser
import bleach  # For HTML sanitization

# --- Configuration ---
config = configparser.ConfigParser()
config.read('server.conf')

PORT = int(config['server']['port'])
MAX_CONNECTIONS = int(config['server']['max_connections'])
MAX_MESSAGE_SIZE = int(config['server']['max_message_size'])
SOCKET_TIMEOUT = int(config['server']['socket_timeout'])
SERVER_CERT = config['tls']['server_cert']
SERVER_KEY = config['tls']['server_key']
ENABLE_TLS = config['tls'].getboolean('enable_tls')

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def sanitize_html(data):
    """Sanitize HTML input using bleach."""
    allowed_tags = bleach.ALLOWED_TAGS + ['p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
    allowed_attributes = bleach.ALLOWED_ATTRIBUTES
    return bleach.clean(data, tags=allowed_tags, attributes=allowed_attributes, strip=True)


def handle_client(client_socket, client_address):
    """Handles communication with a single client."""
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        received_data = b""
        while True:
            try:
                data = client_socket.recv(1024)
            except socket.timeout:
                logging.warning(f"Connection timed out for {client_address}")
                break
            except ConnectionResetError:
                logging.info(f"Connection reset by {client_address}")
                break
            except Exception as e:
                logging.error(f"Error receiving data from {client_address}: {e}")
                break

            if not data:
                logging.info(f"Connection closed by {client_address}")
                break

            received_data += data

            if len(received_data) > MAX_MESSAGE_SIZE:
                logging.warning(f"Client {client_address} exceeded maximum message size. Closing connection.")
                break

            try:
                decoded_data = received_data.decode('utf-8')
            except UnicodeDecodeError as e:
                logging.warning(f"Invalid UTF-8 data received from {client_address}: {e}")
                break

            # Sanitize based on context.  For this example, assume HTML.
            sanitized_data = sanitize_html(decoded_data)
            encoded_data = sanitized_data.encode('utf-8')

            try:
                client_socket.sendall(encoded_data)
                logging.info(f"Echoed data back to {client_address}: {sanitized_data}")
            except Exception as e:
                logging.error(f"Error sending data to {client_address}: {e}")
                break

            break  # Echo once, then close

    except Exception as e:
        logging.error(f"Error handling client {client_address}: {e}")
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            logging.warning(f"Error shutting down socket for {client_address}: {e}")
        client_socket.close()


def echoServer(port):
    """Creates a socket server that echoes back the message sent."""

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', port)
    try:
        server_socket.bind(server_address)
        server_socket.listen(128)
        logging.info(f"Echo server listening on port {port}")

        context = None
        if ENABLE_TLS:
            if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
                logging.error("TLS enabled but server certificate or key not found. Disabling TLS.")
                ENABLE_TLS = False
            else:
                try:
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(SERVER_CERT, SERVER_KEY)
                    # Enable client certificate verification (optional)
                    # context.verify_mode = ssl.CERT_REQUIRED
                    # context.load_verify_locations(CAfile="path/to/ca.pem")
                    logging.info("TLS encryption enabled.")
                except Exception as e:
                    logging.error(f"Error setting up TLS: {e}")
                    ENABLE_TLS = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONNECTIONS) as executor:
            while True:
                client_socket, client_address = server_socket.accept()
                logging.info(f"Accepted connection from {client_address}")

                if ENABLE_TLS and context:
                    try:
                        client_socket = context.wrap_socket(client_socket, server_side=True)
                    except ssl.SSLError as e:
                        logging.error(f"TLS handshake failed with {client_address}: {e}")
                        client_socket.close()
                        continue

                if threading.active_count() > MAX_CONNECTIONS:
                    logging.warning(f"Maximum connection limit reached. Rejecting connection from {client_address}")
                    client_socket.close()
                    continue

                executor.submit(handle_client, client_socket, client_address)

    except OSError as e:
        logging.error(f"Error: Could not bind to port {port}. Another process might be using it. Details: {e}")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server_socket.close()


if __name__ == '__main__':
    echoServer(PORT)

