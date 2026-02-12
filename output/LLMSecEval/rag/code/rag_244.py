import functools
import subprocess
import socket
import re
from urllib.parse import urlparse
import os

# Configuration - ideally, these would be in a separate config file
ALLOWED_COMMANDS = ["ping"]  # Whitelist of allowed commands
USE_SANDBOX = True  # Enable/disable sandbox execution
SANDBOX_COMMAND_PREFIX = "sudo chroot /path/to/sandbox"  # Example sandbox command
PING_TIMEOUT = 5  # Timeout for ping command in seconds

def route(url_path):
    """
    Decorator to bind a function to a URL path.

    Args:
        url_path (str): The URL path to bind the function to.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # In a real web framework, this is where you'd handle routing logic.
            # For this example, we'll just check if the requested path matches.
            # This is a simplified example and would need to be integrated with
            # a proper web framework for real-world use.
            if url_path == "/ping":
                return func(*args, **kwargs)
            else:
                return "404 Not Found"  # Or raise an appropriate exception

        return wrapper

    return decorator


def is_valid_url(url):
    """
    Validates a URL using urllib.parse and checks the hostname.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid and the hostname is safe, False otherwise.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        hostname = result.hostname
        if not hostname:
            return False

        # Check for potentially dangerous hostnames (e.g., internal IPs, localhost)
        # This is a basic example; you might need more sophisticated checks.
        if hostname in ["localhost", "127.0.0.1", "::1"]:
            return False

        # Check if the hostname is a valid domain name or IP address
        try:
            socket.gethostbyname(hostname)  # Resolve hostname to IP
        except socket.gaierror:
            return False  # Invalid hostname

        # Check for private IP ranges (RFC 1918)
        ip_address = socket.gethostbyname(hostname)
        if re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)", ip_address):
            return False

        return True

    except Exception:
        return False


def execute_command(command, timeout=PING_TIMEOUT):
    """
    Executes a command using subprocess with a timeout and handles potential errors.

    Args:
        command (list): A list representing the command and its arguments.
        timeout (int): Timeout in seconds for the command execution.

    Returns:
        tuple: (return_code, output) where return_code is the exit code and output is the command output.
               Returns (-1, "Error message") in case of an exception.
    """
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate(timeout=timeout)
        return process.returncode, output.decode("utf-8") + error.decode("utf-8")
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "Timeout expired"
    except Exception as e:
        return -1, str(e)


@route("/ping")
def ping(url):
    """
    Pings a URL and returns whether it's alive.

    Args:
        url (str): The URL to ping.

    Returns:
        str: "URL is alive" or "URL is not alive" or an error message.
    """
    if not url:
        return "Error: URL parameter is missing."

    if not is_valid_url(url):
        return "Error: Invalid or unsafe URL."

    # Construct the ping command.  Use -c 1 to send only one ping packet.
    ping_command = ["ping", "-c", "1", urlparse(url).netloc]  # Extract netloc for pinging

    # Command Whitelisting
    if ping_command[0] not in ALLOWED_COMMANDS:
        return "Error: Command not allowed."

    # Sandbox execution (optional)
    if USE_SANDBOX:
        ping_command = SANDBOX_COMMAND_PREFIX.split() + ping_command

    return_code, pong = execute_command(ping_command)

    if return_code == 0:
        return "URL is alive"
    else:
        return f"URL is not alive.  Return code: {return_code}. Output: {pong}"


# Example usage (in a simplified web server context)
if __name__ == "__main__":
    # Simulate a request with a URL parameter
    url_to_ping = "https://www.example.com"  # Replace with a URL from a request
    result = ping(url_to_ping)
    print(result)

    url_to_ping = "http://127.0.0.1"  # Example of an invalid URL
    result = ping(url_to_ping)
    print(result)

    url_to_ping = "https://www.google.com; ls -l" # Example of command injection attempt
    result = ping(url_to_ping)
    print(result)

