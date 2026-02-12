import subprocess
import shlex
import json
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import tldextract  # pip install tldextract
import os
import ipaddress # for IP address validation
from flask_cors import CORS # pip install flask-cors
from flask_limiter import Limiter # pip install Flask-Limiter
from flask_limiter.util import get_remote_address
import socket  # Import socket for IP resolution
import tempfile
import logging

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


ALLOWED_DOMAINS = ["example.com", "api.example.com"]
ALLOWED_COMMANDS = ["my_safe_command"]  # Example:  A specific command
ALLOWED_IPS = ["127.0.0.1"]

def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https') and result.netloc
    except:
        return False

def is_allowed_domain(url):
    try:
        result = urlparse(url)
        extracted = tldextract.extract(result.netloc)
        # Check if the registered domain is allowed
        registered_domain = extracted.registered_domain
        return registered_domain in ALLOWED_DOMAINS
    except:
        return False

def is_allowed_ip(ip_address):
    """
    Checks if an IP address is in the allowlist.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return str(ip) in ALLOWED_IPS  # Convert to string for comparison
    except ValueError:
        return False  # Invalid IP address format

def execute_safe_command(command, arguments):
    """Safely executes a command using subprocess."""
    try:
        # Input Validation (Example: Check if arguments are integers)
        for arg in arguments:
            if not isinstance(arg, int):  # Example: Require integer arguments
                try:
                    int(arg)
                except ValueError:
                    return "Error: Argument must be an integer"

        # Create a unique temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Log the command execution
            logger.info(f"Executing command: {command} with arguments: {arguments} in directory: {temp_dir}")

            result = subprocess.run([command] + arguments, capture_output=True, text=True, timeout=10, cwd=temp_dir)  # Pass arguments as a list
            result.check_returncode()  # Raise exception for non-zero exit codes
            return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}, stderr: {e.stderr}") # Log full error
        return "Error: Command execution failed."  # Generic error message for user
    except subprocess.TimeoutExpired:
        logger.error("Command timed out")
        return "Error: Command timed out"
    except Exception as e:
        logger.exception("An unexpected error occurred:") # Log full exception
        return "An unexpected error occurred." # Generic error message for user

@app.route('/execute_command', methods=['POST'])
@limiter.limit("5 per minute")
def execute_command_route():
    command = request.form.get('command')
    argument_string = request.form.get('arguments', '')  # Get arguments as a string

    if not command:
        return jsonify({"error": "Missing 'command' parameter"}), 400

    if command not in ALLOWED_COMMANDS:
        return jsonify({"error": "Command not allowed"}), 403

    # Split the argument string into a list of arguments
    # PROBLEM: This is still vulnerable to arguments with spaces.
    # SOLUTION: Consider using JSON or a different delimiter.
    arguments = argument_string.split()

    output = execute_safe_command(command, arguments)
    return jsonify({"output": output}), 200

@app.route('/validate_url', methods=['POST'])
@limiter.limit("10 per minute")
def validate_url_route():
    url = request.form.get('url')

    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    result = urlparse(url)

    # Correct IP address validation
    try:
        ip_address = socket.gethostbyname(result.netloc.replace("www.", ""))
        logger.info(f"Resolved {result.netloc} to {ip_address}") # Log the resolution
        if ip_address in ALLOWED_IPS:
            logger.info(f"URL {url} allowed based on IP address {ip_address}")
            return jsonify({"message": "URL is valid and allowed (IP)"}), 200
    except socket.gaierror:
        # Log the error for debugging
        logger.error(f"Could not resolve domain {result.netloc} to IP")
        return jsonify({"error": "Could not resolve domain to IP"}), 400

    if not is_allowed_domain(url):
        logger.warning(f"URL {url} not allowed based on domain {result.netloc}")
        return jsonify({"error": "URL domain not allowed"}), 403

    logger.info(f"URL {url} allowed based on domain {result.netloc}")
    return jsonify({"message": "URL is valid and allowed"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

