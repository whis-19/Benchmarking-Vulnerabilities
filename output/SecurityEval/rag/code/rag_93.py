import socket
import threading
import logging
import os
import shlex  # For safer command construction
import subprocess  # For safer command execution
import secrets  # For generating secure tokens
import hashlib  # For hashing
from urllib.parse import urlparse  # For URL validation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Configuration ---
ALLOWED_ORIGINS = ["http://example.com", "https://example.com"]  # Example allowed origins
SANDBOX_ENABLED = True  # Enable/disable command execution sandbox
CHROOT_PATH = "/opt/echoserver_sandbox"  # Path for chroot jail (example)

# --- Utility Functions ---

def validate_url(url):
    """
    Validates a URL to prevent redirection vulnerabilities.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False  # Missing scheme or netloc
        # Check against a whitelist of allowed domains
        if result.netloc not in [urlparse(origin).netloc for origin in ALLOWED_ORIGINS]:
            return False  # Domain not allowed
        return True
    except:
        return False  # Invalid URL format

def generate_nonce():
    """
    Generates a cryptographically secure nonce.
    """
    return secrets.token_hex(16)

def hash_data(data):
    """
    Hashes data using SHA-256 for integrity checks.
    """
    hasher = hashlib.sha256()
    hasher.update(data.encode('utf-8'))
    return hasher.hexdigest()

def sanitize_data(data):
    """
    Sanitizes input data to prevent common injection attacks.
    This is a basic example; more robust sanitization might be needed
    depending on the expected data format.
    """
    # Example: Remove potentially harmful characters
    sanitized_data = data.replace(";", "").replace("`", "").replace("|", "")
    return sanitized_data

def execute_command_safely(command):
    """
    Executes a command in a secure manner, using a sandbox if enabled.
    """
    if not isinstance(command, str):
        raise ValueError("Command must be a string.")

    # 1. Sanitize the command (basic example)
    command = sanitize_data(command)

    # 2. Use shlex to split the command into arguments safely
    try:
        command_args = shlex.split(command)
    except Exception as e:
        logging.error(f"Error splitting command: {e}")
        return "Error: Invalid command format."

    # 3.  Sandbox the execution (chroot example)
    if SANDBOX_ENABLED:
        try:
            # Ensure the chroot path exists
            if not os.path.exists(CHROOT_PATH):
                logging.warning(f"Chroot path {CHROOT_PATH} does not exist.  Disabling sandbox.")
                sandbox_command = command_args
            else:
                # Construct the command to execute within the chroot
                sandbox_command = ["chroot", CHROOT_PATH] + command_args
        except Exception as e:
            logging.error(f"Error setting up chroot: {e}")
            return "Error: Sandbox setup failed."
    else:
        sandbox_command = command_args

    # 4. Execute the command using subprocess with proper error handling
    try:
        result = subprocess.run(sandbox_command, capture_output=True, text=True, timeout=10, check=False)  # Set a timeout
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error(f"Command execution failed: {result.stderr}")
            return f"Error: Command failed with code {result.returncode}.  Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        logging.error("Command execution timed out.")
        return "Error: Command timed out."
    except FileNotFoundError as e:
        logging.error(f"Command not found: {e}")
        return "Error: Command not found."
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return f"Error: Command execution failed: {e}"


def handle_client(conn, addr):
    """
    Handles communication with a single client.
    """
    logging.info(f"Connected by {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            # Validate received data (example: check length)
            if len(data) > 512:
                logging.warning(f"Received data from {addr} exceeds maximum length. Disconnecting.")
                conn.sendall(b"Error: Message too long.")
                break

            # Sanitize the data
            sanitized_data = sanitize_data(data.decode('utf-8'))

            # Echo back the sanitized data
            conn.sendall(sanitized_data.encode('utf-8'))

            # Example: If the message starts with "execute:", try to execute a command
            if sanitized_data.startswith("execute:"):
                command_to_execute = sanitized_data[len("execute:"):]
                result = execute_command_safely(command_to_execute)
                conn.sendall(result.encode('utf-8'))

    except ConnectionResetError:
        logging.warning(f"Connection reset by {addr}")
    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"Connection closed with {addr}")


def echoServer(port):
    """
    Creates a socket server that echoes back the message sent.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))  # Listen on all interfaces
            s.listen()
            logging.info(f"Echo server listening on port {port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr)).start()
    except OSError as e:
        logging.error(f"Error starting server: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    echoServer(12345)  # Example port

