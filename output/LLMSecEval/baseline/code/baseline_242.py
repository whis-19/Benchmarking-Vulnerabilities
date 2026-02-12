import subprocess
import functools
from flask import Flask, request, jsonify
import re
import os

app = Flask(__name__)

# Security Considerations:
# 1. Input Validation:  Sanitize the URL to prevent command injection.
# 2. Whitelisting:  Instead of blacklisting, whitelist allowed characters/domains.
# 3.  Use `subprocess.run` with `shell=False` and explicit arguments.
# 4.  Limit Execution Time:  Prevent indefinite pinging.
# 5.  Logging: Log all ping requests and their results for auditing.
# 6.  Consider Rate Limiting:  Prevent abuse.
# 7.  Principle of Least Privilege:  Run the web application with the minimum necessary permissions.
# 8.  Error Handling:  Handle exceptions gracefully and return informative error messages.
# 9.  Consider using a dedicated ping library (e.g., `python-ping`) for more control and security.
# 10.  Implement proper authentication and authorization to restrict access to the ping functionality.


def validate_url(url):
    """
    Validates the URL to prevent command injection.  This is a *very* basic example.
    A more robust solution would involve a whitelist of allowed domains or a more sophisticated URL parsing library.

    Args:
        url: The URL to validate.

    Returns:
        The validated URL if it's safe, otherwise None.
    """
    # Basic example: Allow only alphanumeric characters, dots, hyphens, and slashes.
    if not re.match(r"^[a-zA-Z0-9\.\-\/]+$", url):
        return None  # Invalid characters found
    
    # Further validation:  Check if it starts with http/https (optional, depending on your needs)
    # if not url.startswith(("http://", "https://")):
    #     return None

    return url


def ping_decorator(f):
    """
    A decorator that handles the URL and executes the ping command.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        url = request.args.get('url')  # Get URL from query parameters

        if not url:
            return jsonify({"error": "URL parameter is missing"}), 400

        validated_url = validate_url(url)
        if not validated_url:
            return jsonify({"error": "Invalid URL format"}), 400

        try:
            output = f(validated_url)  # Pass the validated URL to the ping function
            return jsonify({"result": output})
        except Exception as e:
            print(f"Error during ping: {e}")  # Log the error
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    return wrapper


@app.route('/ping')
@ping_decorator
def ping(url):
    """
    Pings the given URL using the system's ping command.

    Args:
        url: The URL to ping (already validated).

    Returns:
        The output of the ping command.
    """
    try:
        # Use subprocess.run with shell=False for security.
        # Limit the execution time with timeout.
        result = subprocess.run(['ping', '-c', '3', url],  # -c 3 limits to 3 pings
                                  capture_output=True,
                                  text=True,
                                  timeout=10,  # Timeout after 10 seconds
                                  check=True)  # Raise exception on non-zero exit code
        output = result.stdout
        return output
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        return f"Ping failed with error: {e.stderr}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    # It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

