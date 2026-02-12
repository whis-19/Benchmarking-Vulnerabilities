import subprocess
import functools
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secure decorator to bind a function to a URL
def route(url):
    """
    Decorator to bind a function to a URL.

    Args:
        url (str): The URL to bind the function to.
    """
    def decorator(f):
        @app.route(url)
        @functools.wraps(f)  # Preserve original function's metadata
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator


@route("/ping")
def ping():
    """
    Pings a URL and returns whether it is alive.
    """
    url = request.args.get("url")  # Get URL from request parameters

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    # Input validation:  Sanitize the URL to prevent command injection
    # This is crucial for security.  A more robust solution might involve
    # a whitelist of allowed domains or more sophisticated parsing.
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    try:
        # Use subprocess.run with shell=False and explicit arguments to prevent command injection
        result = subprocess.run(["ping", "-c", "1", url],  # -c 1 limits to one ping
                                  capture_output=True,
                                  text=True,
                                  timeout=10)  # Add a timeout to prevent indefinite hanging
        pong = result.stdout  # Capture the output

        if result.returncode == 0:
            return jsonify({"status": "alive", "output": pong})
        else:
            return jsonify({"status": "not alive", "output": pong, "error_code": result.returncode})

    except subprocess.TimeoutExpired:
        return jsonify({"status": "timeout", "error": "Ping timed out"}), 504  # Gateway Timeout
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500  # Internal Server Error


def is_valid_url(url):
    """
    Basic URL validation to prevent command injection.  This is a MINIMAL example.
    A production system should use a more robust URL parsing library.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL appears valid, False otherwise.
    """
    # Check for obvious command injection attempts
    if any(char in url for char in "&;`|><$(){}[]\\\"'"):
        return False

    # Check if the URL starts with a valid scheme (http, https) or is a hostname
    if url.startswith(("http://", "https://")):
        return True

    # Allow hostnames (e.g., google.com)
    import re
    hostname_pattern = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$"
    )
    if hostname_pattern.match(url):
        return True

    return False


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

