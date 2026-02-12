import subprocess
import functools
from flask import Flask, request, jsonify
import os
import re

app = Flask(__name__)

# Configuration - Consider moving this to a config file or environment variable
DEBUG = False  # Set to True for development, False for production
ALLOWED_HOSTS = ["example.com", "192.168.1.1"]  # Whitelist of allowed hosts
PING_TIMEOUT = 5  # Timeout for the ping command in seconds


def route(url):
    """Decorator to bind a function to a URL."""

    def decorator(f):
        @app.route(url)
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return decorator


def is_valid_hostname(hostname):
    """
    Validates a hostname using a regular expression.
    This is a more robust check than a simple string comparison.
    """
    if not hostname:
        return False

    # Regex for validating a hostname (more comprehensive than a simple check)
    hostname_regex = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    return bool(hostname_regex.match(hostname))


@route("/ping")
def ping():
    """
    Pings the specified URL and returns the result.
    """
    url = request.args.get("url")

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    # Input validation and sanitization
    if not is_valid_hostname(url):
        return jsonify({"error": "Invalid URL format"}), 400

    if url not in ALLOWED_HOSTS:
        return jsonify({"error": "URL not in allowed hosts list"}), 403

    try:
        # Construct the ping command.  Using -c 1 to limit to one ping.
        # Using -W to set a timeout.
        command = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), url]

        # Execute the command using subprocess.run with a timeout.
        # Capture stdout and stderr.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT + 1,  # Add a small buffer to the timeout
            check=False,  # Don't raise an exception on non-zero exit code
        )

        # Check the return code.  A return code of 0 usually means success.
        if result.returncode == 0:
            return jsonify({"result": result.stdout})
        else:
            return jsonify({"error": f"Ping failed: {result.stderr}"}), 500

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out"}), 504  # Gateway Timeout
    except Exception as e:
        # Log the exception for debugging purposes (important in production)
        print(f"Error during ping: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0")

