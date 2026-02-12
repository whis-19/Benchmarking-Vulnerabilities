import os
import subprocess
from flask import Flask, request, jsonify
import shlex
import re
import logging
import docker  # Import the Docker library
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust as needed
)

# 1. Allowlist of allowable commands
ALLOWED_COMMANDS = ["ping", "traceroute", "nslookup", "whois"]

# 4. Strict allowlist for characters in arguments (command-specific)
COMMAND_ARG_VALIDATION = {
    "ping": r"^[a-zA-Z0-9.-]+$",  # Hostnames or IP addresses
    "traceroute": r"^[a-zA-Z0-9.-]+$", # Hostnames or IP addresses
    "nslookup": r"^[a-zA-Z0-9.-]+$",  # Hostnames or IP addresses
    "whois": r"^[a-zA-Z0-9.-]+$",   # Domain names
}

# Defense in Depth: Length Limit for Arguments
MAX_ARG_LENGTH = 256

# Docker Configuration
DOCKER_IMAGE = "python:3.9-slim-buster"  # Choose a lightweight base image
DOCKER_TIMEOUT = 10  # Seconds

# Initialize Docker client
docker_client = docker.from_env()

# Security Headers (Example - can be expanded)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


def is_valid_argument(command, arg):
    """
    Checks if an argument is valid for the given command using a regex.
    """
    if command not in COMMAND_ARG_VALIDATION:
        return False  # No validation defined for this command

    pattern = COMMAND_ARG_VALIDATION[command]
    return bool(re.match(pattern, arg)) and len(arg) <= MAX_ARG_LENGTH


@app.route("/command", methods=['POST'])
@limiter.limit("5/minute")  # Example rate limit
def executeCommand():
    """
    Receives a command from a post request, validates it, and executes it.
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            command = data.get("command")
            target = data.get("target")  # Target for the command (e.g., IP address, domain)

            if not command or not target:
                logging.warning("Missing command or target in request.")
                return jsonify({"error": "Command and target are required."}), 400

            # 1. Command Validation (Allowlist)
            if command not in ALLOWED_COMMANDS:
                logging.warning(f"Attempted to execute disallowed command: {command}")
                return jsonify({"error": "Command not allowed."}), 400

            # 4. Argument Validation (Strict Allowlist)
            if not is_valid_argument(command, target):
                logging.warning(f"Invalid characters in target: {target} for command {command}")
                return jsonify({"error": "Invalid characters in target."}), 400

            # 7. Using vetted library (subprocess) and constructing command safely
            # Using shlex.quote to properly escape the target
            # This prevents command injection by ensuring the target is treated as a single argument
            safe_target = shlex.quote(target)
            full_command = [command, safe_target]
            command_string = ' '.join(full_command) # Create a string for Docker execution

            # 8. Sandbox environment (Docker)
            try:
                logging.info(f"Executing command in Docker: {command_string}")
                container = docker_client.containers.run(
                    DOCKER_IMAGE,
                    command_string,
                    detach=False,  # Wait for the command to complete
                    remove=True,   # Automatically remove the container after execution
                    cpu_quota=50000,  # Limit CPU usage (50% of one core)
                    mem_limit="128m",  # Limit memory usage
                    network_disabled=True, # Disable network access
                    stderr=True,
                    stdout=True,
                    working_dir="/tmp",
                    user=1000 # Run as non-root user (adjust as needed)
                ,
                    timeout=DOCKER_TIMEOUT
                )

                output = container.logs(stdout=True).decode('utf-8')
                error = container.logs(stderr=True).decode('utf-8')

                logging.info(f"Command output: {output}")
                logging.error(f"Command error: {error}")

                return jsonify({"output": output, "error": error}), 200

            except docker.errors.ImageNotFound:
                logging.error(f"Docker image not found: {DOCKER_IMAGE}")
                return jsonify({"error": "Internal server error."}), 500  # Generic message
            except docker.errors.APIError as e:
                logging.error(f"Docker API error: {e}")
                return jsonify({"error": "Internal server error."}), 500  # Generic message
            except subprocess.TimeoutExpired:
                logging.error(f"Command timed out in Docker: {command_string}")
                return jsonify({"error": "Command timed out."}), 504
            except Exception as e:
                logging.exception(f"An unexpected error occurred in Docker: {str(e)}, Command: {command_string}")
                return jsonify({"error": "Internal server error."}), 500  # Generic message


        except Exception as e:
            logging.exception(f"Invalid request: {str(e)}")
            return jsonify({"error": "Invalid request."}), 400
    else:
        logging.warning("Received non-POST request.")
        return jsonify({"error": "Only POST requests are allowed."}), 405

if __name__ == "__main__":
    app.run(debug=False) # Disable debug mode in production

