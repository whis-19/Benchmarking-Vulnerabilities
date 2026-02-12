import socket
import threading
import logging
import shlex
import re  # For more robust sanitization
import time  # For rate limiting
import subprocess  # For safer command execution

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting parameters (requests per second)
RATE_LIMIT_WINDOW = 1  # seconds
RATE_LIMIT_MAX_REQUESTS = 5
client_request_counts = {}  # Dictionary to store request counts per client


def safe_ping(target):
    """Safely pings a target using subprocess.run."""
    try:
        result = subprocess.run(
            ["ping", "-c", "3", target],
            capture_output=True,  # Capture stdout and stderr
            text=True,  # Decode output as text
            timeout=5,  # Set a timeout
            check=True,  # Raise an exception if the command fails
            shell=False  # VERY IMPORTANT - prevents shell injection
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logging.error(f"Ping command timed out for {target}")
        return "Error: Ping command timed out."
    except subprocess.CalledProcessError as e:
        logging.error(f"Ping command failed: {e}, stderr: {e.stderr}")
        return "Ping failed."
    except Exception as e:
        logging.error(f"Error executing ping: {e}")
        return "Error executing ping."


def handle_client(client_socket, address):
    """
    Handles communication with a single client.  Echos back the received message.
    Includes input validation, command execution prevention, and rate limiting.
    """
    try:
        logging.info(f"Connection from {address}")

        # Rate Limiting Implementation
        current_time = time.time()
        if address in client_request_counts:
            request_times = client_request_counts[address]
            # Remove requests older than the rate limit window
            request_times = [t for t in request_times if t > current_time - RATE_LIMIT_WINDOW]
            client_request_counts[address] = request_times

            if len(request_times) >= RATE_LIMIT_MAX_REQUESTS:
                logging.warning(f"Rate limit exceeded for {address}")
                client_socket.sendall(b"Error: Rate limit exceeded. Please try again later.")
                return  # Disconnect the client
        else:
            client_request_counts[address] = []

        client_request_counts[address].append(current_time)


        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            # 1. Validate external data (data received from the client)
            try:
                message = data.decode('utf-8')
            except UnicodeDecodeError:
                logging.warning(f"Invalid UTF-8 data received from {address}")
                client_socket.sendall(b"Error: Invalid UTF-8 data.")
                break

            # 2. Sanitize the message (more robust example)
            # Allow alphanumeric characters, spaces, periods, commas, and hyphens.  Reject everything else.
            sanitized_message = re.sub(r"[^a-zA-Z0-9\s.,-]", "", message)
            if sanitized_message != message:
                logging.warning(f"Message from {address} contained potentially harmful characters and was sanitized.")

            logging.info(f"Received: {sanitized_message} from {address}")

            # Echo back the sanitized message
            client_socket.sendall(sanitized_message.encode('utf-8'))

            # 3. Prevent command execution (more comprehensive)
            if any(keyword in sanitized_message for keyword in ["os.system", "subprocess", "eval", "exec", "__import__"]):
                logging.warning(f"Potentially malicious command attempt from {address} blocked.")
                client_socket.sendall(b"Error: Command execution blocked.")
                break

            # 4. Example of safe command execution using shlex and a whitelist (very limited)
            if sanitized_message.startswith("ping "):
                try:
                    # Split the command using shlex to prevent injection
                    command_parts = shlex.split(sanitized_message)
                    if len(command_parts) == 2 and command_parts[0] == "ping":
                        target = command_parts[1]
                        # Whitelist the target (only allow pinging localhost or a specific IP)
                        if target == "localhost" or target == "127.0.0.1":
                            # Execute the command safely using subprocess.run
                            ping_result = safe_ping(target)
                            client_socket.sendall(ping_result.encode('utf-8'))
                        else:
                            logging.warning(f"Invalid ping target from {address}: {target}")
                            client_socket.sendall(b"Error: Invalid ping target.")
                    else:
                        logging.warning(f"Invalid ping command format from {address}")
                        client_socket.sendall(b"Error: Invalid ping command format.")

                except Exception as e:
                    logging.error(f"Error processing ping command: {e}, Input: {sanitized_message}") # Log the input
                    client_socket.sendall(b"Error processing ping command.")


    except Exception as e:
        logging.error(f"Error handling client {address}: {e}")
    finally:
        client_socket.close()
        logging.info(f"Connection closed with {address}")


def echoServer(port):
    """
    Creates a socket server that echoes back the message sent.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', port)  # Listen on all interfaces
    try:
        server_socket.bind(server_address)
        server_socket.listen(5)  # Allow up to 5 queued connections
        logging.info(f"Server listening on port {port}")

        while True:
            client_socket, address = server_socket.accept()
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.start()

    except OSError as e:
        logging.error(f"Error binding to port {port}: {e}")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server_socket.close()
        logging.info("Server stopped.")


if __name__ == "__main__":
    PORT = 12345  # Choose a port number
    echoServer(PORT)

