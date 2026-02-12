import functools
import subprocess
import socket
import re
from urllib.parse import urlparse
import os

# Configuration - Ideally, these should be set via environment variables or a config file
ALLOWED_COMMANDS = ["ping"]  # Allowlist of commands
USE_SANDBOX = True  # Enable sandboxing (requires setup)
SANDBOX_PATH = "/opt/ping_sandbox"  # Path to the sandbox environment
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
            # This is where you would integrate with your web framework
            # For example, if using Flask:
            # from flask import request
            # if request.path == url_path:
            #     return func(*args, **kwargs)
            # else:
            #     return "404 Not Found"

            # For demonstration purposes, we'll just call the function directly
            # if the provided url_path matches a predefined route.
            if url_path == "/ping":
                return func(*args, **kwargs)
            else:
                return "404 Not Found"

        return wrapper
    return decorator


def is_valid_hostname(hostname):
    """
    Validates a hostname using a regular expression.  This is a basic check
    and might need to be adjusted based on specific requirements.

    Args:
        hostname (str): The hostname to validate.

    Returns:
        bool: True if the hostname is valid, False otherwise.
    """
    if not hostname:
        return False
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def is_valid_url(url):
    """
    Validates a URL by parsing it and checking the hostname.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid and the hostname is safe, False otherwise.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        hostname = result.netloc.split(':')[0]  # Remove port if present
        return is_valid_hostname(hostname)

    except Exception:
        return False


def ping_url(url):
    """
    Pings a URL using the 'ping' command.

    Args:
        url (str): The URL to ping.

    Returns:
        str: "Alive" if the URL is reachable, "Not Alive" otherwise.  Returns "Invalid URL" if the URL is invalid.
    """

    if not is_valid_url(url):
        return "Invalid URL"

    try:
        hostname = urlparse(url).netloc.split(':')[0] # Extract hostname

        # Command construction (using vetted library and escaping)
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), hostname]

        # Sandbox execution (if enabled)
        if USE_SANDBOX:
            # Ensure the sandbox directory exists
            if not os.path.exists(SANDBOX_PATH):
                return "Sandbox Error: Sandbox path does not exist."

            # Create a chroot environment (requires root privileges to set up properly)
            # This is a simplified example and requires proper setup of the sandbox environment.
            try:
                # Change the root directory to the sandbox
                os.chroot(SANDBOX_PATH)
                # Change the current working directory to the new root
                os.chdir("/")
            except OSError as e:
                return f"Sandbox Error: Failed to chroot: {e}"

        # Execute the command using subprocess.run (safer than subprocess.call/Popen)
        process = subprocess.run(command, capture_output=True, text=True, timeout=PING_TIMEOUT)

        # Check the return code
        if process.returncode == 0:
            return "Alive"
        else:
            return "Not Alive"

    except subprocess.TimeoutExpired:
        return "Not Alive (Timeout)"
    except Exception as e:
        return f"Error: {e}"


@route("/ping")
def ping(url):
    """
    Pings the specified URL and returns the result.

    Args:
        url (str): The URL to ping.

    Returns:
        str: "Alive" if the URL is reachable, "Not Alive" otherwise, or "Invalid URL" if the URL is invalid.
    """
    return ping_url(url)


if __name__ == '__main__':
    # Example usage (simulating a web request)
    url_to_ping = "http://www.google.com"  # Replace with a URL from a request
    result = ping(url_to_ping)
    print(f"Pinging {url_to_ping}: {result}")

    url_to_ping = "http://invalid-domain-that-does-not-exist.com"
    result = ping(url_to_ping)
    print(f"Pinging {url_to_ping}: {result}")

    url_to_ping = "invalid url"
    result = ping(url_to_ping)
    print(f"Pinging {url_to_ping}: {result}")

    # Example of a potentially malicious URL (should be blocked by validation)
    url_to_ping = "http://www.google.com; ls -l"
    result = ping(url_to_ping)
    print(f"Pinging {url_to_ping}: {result}")

    url_to_ping = "http://localhost"
    result = ping(url_to_ping)
    print(f"Pinging {url_to_ping}: {result}")

