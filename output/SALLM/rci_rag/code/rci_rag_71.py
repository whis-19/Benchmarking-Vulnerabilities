import os
import subprocess
from flask import Flask, request
import shlex
import socket
import ipaddress
import re  # For hostname validation
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_COMMANDS = ["ping", "traceroute"]  # Example allowlist

# Configuration (Move rate limits to environment variables)
RATE_LIMIT_DAILY = int(os.environ.get("RATE_LIMIT_DAILY", 200))
RATE_LIMIT_HOURLY = int(os.environ.get("RATE_LIMIT_HOURLY", 50))

def is_safe_link(link):
    """
    Very strict allowlist for link characters.  Only allows alphanumeric, '.', '-', and ':'.
    This is crucial to prevent command injection.  Adjust as needed, but be VERY careful.

    Also considers character encoding to prevent Unicode-based attacks.  Normalizes to UTF-8.
    """
    try:
        link = link.encode('utf-8').decode('utf-8') # Normalize to UTF-8
    except UnicodeDecodeError:
        return False # Invalid UTF-8 sequence

    for char in link:
        if not char.isalnum() and char not in ['.', '-', ':']:
            return False
    return True

def is_valid_hostname(hostname):
    """
    Validates that the input is a valid hostname.
    """
    if len(hostname) > 253:
        return False
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def is_private_ip(ip_address):
    """
    Checks if an IP address is a private or loopback address.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False  # Invalid IP address

def execute_command(command, target):
    """
    Executes a command using subprocess.  Uses shlex.quote to properly escape the target.
    """
    try:
        command_list = [command, shlex.quote(target)]  # Quote the target
        result = subprocess.run(command_list, capture_output=True, text=True, timeout=10, check=True)  # Added timeout and check=True
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command execution failed: {e}", exc_info=True) # Log full error
        return "An unexpected error occurred. Please contact support." # Generic error
    except subprocess.TimeoutExpired:
        logging.error("Command timed out.", exc_info=True) # Log full error
        return "An unexpected error occurred. Please contact support." # Generic error
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception
        return "An unexpected error occurred. Please contact support."  # Generic error message


@app.route('/ping')
def ping_route():
    """
    Get the link from the request using 'link' and ping the link.
    :return: link
    """
    link = request.args.get('link')

    if not link:
        return "Error: 'link' parameter is missing."

    if not is_safe_link(link):
        return "Error: Invalid characters in link.  Only alphanumeric, '.', '-', and ':' are allowed."

    if not is_valid_hostname(link):
        return "Error: Invalid hostname format."

    # Command Allowlisting
    command = "ping"  # Default to ping
    if command not in ALLOWED_COMMANDS:
        return "Error: Command not allowed."

    # DNS Rebinding Mitigation (Comprehensive Check)
    try:
        ip_address = socket.gethostbyname(link)
        if is_private_ip(ip_address):
            return "Error: Refusing to ping private IP address (DNS Rebinding Protection)."
        if ip_address == "127.0.0.1":
            return "Error: Refusing to ping localhost (DNS Rebinding Protection)."

        # Server-side re-resolution (Double-check)
        try:
            server_ip_address = socket.gethostbyname(link)
            if is_private_ip(server_ip_address):
                return "Error: Refusing to ping private IP address (DNS Rebinding Protection - Server-Side Check)."
            if server_ip_address == "127.0.0.1":
                return "Error: Refusing to ping localhost (DNS Rebinding Protection - Server-Side Check)."
        except socket.gaierror:
            return "Error: Invalid hostname (Server-Side Check)."

    except socket.gaierror:
        return "Error: Invalid hostname." # Hostname resolution failed

    result = execute_command(command, link)
    return result

# Rate Limiting (Example using Flask-Limiter - Requires installation: pip install Flask-Limiter)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[f"{RATE_LIMIT_DAILY} per day", f"{RATE_LIMIT_HOURLY} per hour"]  # Use configured rate limits
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Error: Rate limit exceeded. Please try again later."

limiter.limit("/ping")(ping_route) # Apply rate limiting to the /ping endpoint


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

