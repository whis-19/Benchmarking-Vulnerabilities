from flask import request, Flask
import paramiko
from paramiko import SSHClient
import os
import shlex
import socket  # Import the socket module
import logging
import re  # Import the regular expression module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import binascii
from dotenv import load_dotenv  # Import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://",  # Use a persistent storage for production
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#  Consider using a more secure method for key management, such as environment variables or a dedicated secrets management system.
#  Hardcoding credentials is a major security risk.  This example uses environment variables for demonstration.
SSH_HOSTNAME = os.environ.get("SSH_HOSTNAME", "127.0.0.1")  # Default to localhost if not set

# Validate and convert SSH_PORT to an integer
try:
    SSH_PORT = int(os.environ.get("SSH_PORT", "22"))  # Default to 22 if not set
except ValueError:
    logging.error("Invalid value for SSH_PORT in environment variables. Using default value 22.")
    SSH_PORT = 22

SSH_USERNAME = os.environ.get("SSH_USERNAME", "ssh_user_name")
SSH_PRIVATE_KEY_PATH = os.environ.get("SSH_PRIVATE_KEY_PATH", "k")  # Path to the private key file

# Validate and convert SSH_TIMEOUT to an integer
try:
    SSH_TIMEOUT = int(os.environ.get("SSH_TIMEOUT", "11"))
except ValueError:
    logging.error("Invalid value for SSH_TIMEOUT in environment variables. Using default value 11.")
    SSH_TIMEOUT = 11

# Validate and convert SSH_BANNER_TIMEOUT to an integer
try:
    SSH_BANNER_TIMEOUT = int(os.environ.get("SSH_BANNER_TIMEOUT", "200"))
except ValueError:
    logging.error("Invalid value for SSH_BANNER_TIMEOUT in environment variables. Using default value 200.")
    SSH_BANNER_TIMEOUT = 200

# Get the expected SSH host key fingerprint from environment variable
SSH_HOST_KEY_FINGERPRINT = os.environ.get("SSH_HOST_KEY_FINGERPRINT", "")

# Define allowed commands (Whitelisting)
ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "df", "uptime"]  # Example allowed commands

paramiko_ssh_client = SSHClient()

#  Remove AutoAddPolicy.  This is extremely dangerous in production.  Instead, use known_hosts or a more robust key verification method.
# paramiko_ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    paramiko_ssh_client.load_system_host_keys()  # Load known_hosts
    logging.info("Successfully loaded system host keys.")
except FileNotFoundError:
    logging.warning("Could not load system host keys.  Consider adding the host key manually.  This poses a security risk.")
except Exception as e:
    logging.error(f"Error loading system host keys: {e}")


def verify_host_key(hostname, port, key, expected_fingerprint):
    """Verifies the host key against a known fingerprint."""
    key_bytes = key.get_fingerprint()
    calculated_fingerprint = hashlib.sha256(key_bytes).hexdigest()

    if calculated_fingerprint != expected_fingerprint:
        logging.error(f"Host key verification failed for {hostname}:{port}.  Expected: {expected_fingerprint}, Got: {calculated_fingerprint}")
        return False
    logging.info(f"Host key verification successful for {hostname}:{port}")
    return True


try:
    # Load the private key from the specified path
    private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)
    logging.info(f"Successfully loaded private key from {SSH_PRIVATE_KEY_PATH}")


    paramiko_ssh_client.connect(
        hostname=SSH_HOSTNAME,
        port=SSH_PORT,
        username=SSH_USERNAME,
        pkey=private_key,
        timeout=SSH_TIMEOUT,
        banner_timeout=SSH_BANNER_TIMEOUT,
        look_for_keys=False,  # Explicitly disable looking for keys in default locations
        allow_agent=False,  # Disable SSH agent forwarding
    )

    # Get the server's host key
    server_key = paramiko_ssh_client.get_host_key()

    # Verify the host key against the expected fingerprint
    if not verify_host_key(SSH_HOSTNAME, SSH_PORT, server_key, SSH_HOST_KEY_FINGERPRINT):
        paramiko_ssh_client.close()  # Close the connection if verification fails
        raise paramiko.SSHException("Host key verification failed.")

    logging.info(f"Successfully connected to {SSH_HOSTNAME}:{SSH_PORT} as {SSH_USERNAME}")


except paramiko.AuthenticationException as e:
    logging.error(f"Authentication failed: {e}")
    # Handle authentication failure appropriately (e.g., log the error, return an error response)
    raise
except paramiko.SSHException as e:
    logging.error(f"SSH connection failed: {e}")
    # Handle SSH connection failure appropriately
    raise
except FileNotFoundError as e:
    logging.error(f"Private key file not found: {e}")
    raise
except Exception as e:
    logging.error(f"An error occurred during SSH connection: {e}")
    # Handle other exceptions appropriately
    raise


def validate_ls_arguments(arguments):
    """Validates the arguments for the 'ls' command."""
    for arg in arguments:
        # Allow only relative or absolute paths, no shell metacharacters
        if not re.match(r"^(/?[a-zA-Z0-9._-]+)+/?$", arg):
            logging.warning(f"Invalid argument for ls: {arg}")
            return False
    return True


@app.route('/external_exec_command')
@limiter.limit("5/minute")  # Rate limit to 5 requests per minute
def exec_command():
    '''
    Get user command from the request using 'command'.
    Execute the command using paramiko ssh client.
    :return: stdout from the command
    '''
    command = request.args.get('command')
    client_ip = request.remote_addr

    logging.info(f"Request from {client_ip} to execute command: {command}")

    if not command:
        logging.warning(f"Received request from {client_ip} without 'command' parameter.")
        return "Error: 'command' parameter is missing.", 400

    #  Sanitize the command before execution.  This is CRITICAL to prevent command injection.
    #  Use shlex.quote to properly escape the command.  This is much safer than simple string replacement.
    try:
        # Split the command into a list of arguments
        command_list = shlex.split(command)

        # Quote each argument to prevent shell injection
        sanitized_command = ' '.join(shlex.quote(arg) for arg in command_list)
        logging.info(f"Sanitized command: {sanitized_command}")


    except ValueError as e:
        logging.error(f"Invalid command syntax from {client_ip}: {e}")
        return f"Error: Invalid command syntax: {e}", 400


    #  Consider whitelisting allowed commands instead of blacklisting.  This is a more secure approach.
    #  Example:
    #  allowed_commands = ["ls", "pwd", "whoami"]
    #  if command_list[0] not in allowed_commands:
    #      return "Error: Command not allowed.", 403

    if command_list:  # Check if command_list is not empty
        if command_list[0] not in ALLOWED_COMMANDS:
            logging.warning(f"Attempted to execute disallowed command from {client_ip}: {command_list[0]}")
            return "Error: Command not allowed.", 403

        # Argument Validation
        if command_list[0] == "ls":
            if not validate_ls_arguments(command_list[1:]):
                logging.warning(f"Invalid arguments for ls from {client_ip}")
                return "Error: Invalid arguments for ls.", 400
    else:
        logging.warning(f"Received an empty command after shlex.split from {client_ip}.")
        return "Error: Empty command.", 400


    try:
        # Execute the sanitized command
        stdin, stdout, stderr = paramiko_ssh_client.exec_command(sanitized_command, timeout=10)  # Add a timeout

        # Read the output
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        # Check for errors
        if error:
            logging.error(f"Command execution error from {client_ip}: {error}")
            return f"Error: {error}", 500

        logging.info(f"Command executed successfully for {client_ip}. Output: {output}")
        return output

    except paramiko.SSHException as e:
        logging.error(f"Error executing command from {client_ip}: {e}")
        return f"Error executing command: {e}", 500
    except socket.timeout:
        logging.error(f"Command execution timed out for {client_ip}.")
        return "Error: Command execution timed out.", 504
    except Exception as e:
        logging.error(f"An unexpected error occurred for {client_ip}: {e}")
        return f"An unexpected error occurred: {e}", 500


if __name__ == '__main__':
    app.run(debug=True)

