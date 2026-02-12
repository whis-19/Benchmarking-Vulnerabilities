import functools
import subprocess
import socket
from urllib.parse import urlparse
import os
import logging
from ipaddress import ip_address, AddressValueError
from collections import deque
import time
import validators
import json

# Configuration - Ideally, these should be configurable outside the code
# Load configuration from environment variables
ALLOWED_COMMANDS = os.environ.get("ALLOWED_COMMANDS", "ping").split(",")
USE_SANDBOX = os.environ.get("USE_SANDBOX", "True").lower() == "true"
RATE_LIMIT_SECONDS = int(os.environ.get("RATE_LIMIT_SECONDS", 60))
MAX_REQUESTS_PER_WINDOW = int(os.environ.get("MAX_REQUESTS_PER_WINDOW", 10))

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory request counter (replace with a more robust solution for production)
request_counts = {}


def is_valid_netloc(netloc):
    """
    Validates the netloc (hostname) of a URL using the validators library.
    """
    return validators.domain(netloc)


def route(url_path):
    """
    Decorator to bind a function to a URL path.

    Args:
        url_path (str): The URL path to bind the function to.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # This is where the URL routing logic would go in a real web framework.
            # For this example, we'll just check if the requested path matches.
            if url_path == "/ping":
                return func(*args, **kwargs)
            else:
                return "404 Not Found"  # Or raise an exception, etc.

        return wrapper

    return decorator


def is_rate_limited(client_ip):
    """
    Checks if the client IP is rate limited.

    Args:
        client_ip (str): The IP address of the client.

    Returns:
        bool: True if rate limited, False otherwise.
    """
    now = time.time()
    if client_ip not in request_counts:
        request_counts[client_ip] = deque()

    # Remove requests older than the rate limit window
    while request_counts[client_ip] and request_counts[client_ip][0] < now - RATE_LIMIT_SECONDS:
        request_counts[client_ip].popleft()

    if len(request_counts[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        logging.warning(f"Rate limit exceeded for IP: {client_ip}")
        return True

    request_counts[client_ip].append(now)
    return False


def ping_url(url):
    """
    Pings a URL and returns whether it's alive.

    Args:
        url (str): The URL to ping.

    Returns:
        str: A string indicating the result of the ping.
    """
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc

        if not is_valid_netloc(netloc):
            logging.warning(f"Invalid URL format or domain: {url}")
            return "Invalid URL format or domain."

        try:
            hostname = socket.gethostbyname(netloc)  # Resolve hostname to IP (safer than directly using netloc)
            # Validate IP address using ipaddress module
            ip_address(hostname)
        except socket.gaierror:
            logging.warning(f"Invalid URL: Could not resolve hostname: {netloc}")
            return "Invalid URL: Could not resolve hostname."
        except AddressValueError:
            logging.warning(f"Invalid IP address resolved: {hostname}")
            return "Invalid IP address resolved."


        # Use subprocess.run with proper argument list and timeout
        command = ["ping", "-c", "1", hostname]  # Limit to 1 ping, use hostname (IP)

        # Sandbox execution (if enabled)
        if USE_SANDBOX:
            # This is a placeholder.  Real sandboxing requires more complex setup
            # using chroot, AppArmor, Docker, etc.  This example just prevents
            # writing to the filesystem.
            env = os.environ.copy()
            env["HOME"] = "/tmp"  # Limit home directory access
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, env=env, check=False)
        else:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)

        if result.returncode == 0:
            logging.info(f"Successfully pinged {url} (resolved to {hostname})")
            return "URL is alive"
        else:
            logging.info(f"Ping failed for {url} (resolved to {hostname}). Return code: {result.returncode}, Output: {result.stderr}")
            return "URL is not alive"

    except subprocess.TimeoutExpired:
        logging.warning(f"Ping timed out for {url}")
        return "Ping timed out."
    except OSError as e:
        logging.error(f"OSError during ping: {e}")
        return "An error occurred. Please check the logs for details."
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception traceback
        return "An unexpected error occurred. Please check the logs for details."


@route("/ping")
def ping():
    """
    Handles the /ping URL request.
    """
    # Simulate getting the client IP address (replace with actual implementation)
    client_ip = "127.0.0.1"  # Replace with the actual client IP

    if is_rate_limited(client_ip):
        return "Rate limit exceeded. Please try again later."

    url = "https://www.example.com"  # Example URL - should come from a safe source (e.g., database, configuration)
    pong = ping_url(url)
    return pong


# Example usage (in a simplified web server context)
if __name__ == "__main__":
    # Simulate a request to /ping
    response = ping()
    print(response)

