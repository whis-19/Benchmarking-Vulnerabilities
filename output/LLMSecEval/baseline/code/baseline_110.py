import subprocess
import functools
from flask import Flask, request, jsonify
import os
import re

app = Flask(__name__)

# Configuration - Ideally, these should come from environment variables or a config file
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
    Validates a hostname against common injection patterns.
    This is a basic example and can be expanded for more robust validation.
    """
    if not hostname:
        return False

    # Check for shell metacharacters
    if any(char in hostname for char in ['&', ';', '|', '>', '<', '`', '$', '!', '"', "'", '\\', '[', ']']):
        return False

    # Check for IP address format (more robust than just checking for dots)
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        return True  # It's a valid IP address
    except ValueError:
        pass  # Not an IP address

    # Basic hostname validation (letters, numbers, hyphens, dots)
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        return False

    # Check for excessive length
    if len(hostname) > 253:  # Maximum hostname length
        return False

    return True


def is_allowed_host(hostname):
    """
    Checks if the hostname is in the allowed list.
    """
    return hostname in ALLOWED_HOSTS


@route('/ping')
def ping():
    """
    Pings the specified URL and returns the result.
    """
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    if not is_valid_hostname(url):
        return jsonify({"error": "Invalid URL format"}), 400

    if not is_allowed_host(url):
        return jsonify({"error": "URL is not in the allowed list"}), 403

    try:
        # Construct the ping command.  Using shell=False is crucial for security.
        # We pass the URL as a separate argument to prevent shell injection.
        command = ['ping', '-c', '3', url]  # Limit to 3 pings
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        output, error = process.communicate(timeout=PING_TIMEOUT)  # Add a timeout

        if process.returncode == 0:
            return jsonify({"result": output.decode('utf-8')})
        else:
            return jsonify({"error": f"Ping failed: {error.decode('utf-8')}"}), 500

    except subprocess.TimeoutExpired:
        process.kill()  # Ensure the process is killed if it times out
        return jsonify({"error": "Ping timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    #  Never run this in production with debug=True.  It's a security risk.
    app.run(debug=False, host='0.0.0.0', port=5000)

