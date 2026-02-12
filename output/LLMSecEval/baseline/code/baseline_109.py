import subprocess
import functools
from flask import Flask, request, jsonify
import re
import os

app = Flask(__name__)

# Security Considerations:
# 1. Input Validation:  Sanitize the URL to prevent command injection.
# 2. Use `subprocess.run` with `shell=False`:  Avoid shell injection vulnerabilities.
# 3. Limit Allowed Characters:  Restrict the characters allowed in the URL.
# 4. Timeouts:  Set timeouts for the ping command to prevent denial-of-service.
# 5. Logging: Log all ping requests and their results for auditing.
# 6. Consider using a dedicated ping library:  Libraries like `python-ping` might offer safer alternatives.
# 7. Principle of Least Privilege:  Run the web application with the least necessary privileges.
# 8. Rate Limiting: Implement rate limiting to prevent abuse.
# 9.  Consider using a whitelist of allowed domains instead of a blacklist.

ALLOWED_CHARACTERS = r"^[a-zA-Z0-9\.\-]+$"  # Allow alphanumeric, dots, and hyphens
MAX_PING_TIME = 5  # Maximum time (seconds) to allow the ping command to run

def validate_url(url):
    """
    Validates the URL to prevent command injection.  Only allows alphanumeric characters, dots, and hyphens.
    """
    if not re.match(ALLOWED_CHARACTERS, url):
        return False, "Invalid URL: Only alphanumeric characters, dots, and hyphens are allowed."
    return True, None


def ping_decorator(f):
    """
    A decorator that handles pinging a URL.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        url = request.args.get('url')  # Get the URL from the query parameters

        if not url:
            return jsonify({"error": "URL parameter is missing."}), 400

        is_valid, error_message = validate_url(url)
        if not is_valid:
            return jsonify({"error": error_message}), 400

        try:
            output = f(url)
            return jsonify({"result": output})
        except Exception as e:
            print(f"Error during ping: {e}")  # Log the error
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    return wrapper


@app.route("/ping")
@ping_decorator
def ping(url):
    """
    Pings the given URL using the system's ping command.
    """
    try:
        # Use subprocess.run with shell=False for security
        result = subprocess.run(['ping', '-c', '3', url],  # Limit to 3 pings
                                  capture_output=True,
                                  text=True,
                                  timeout=MAX_PING_TIME,
                                  check=True)  # Raise an exception on non-zero exit code

        output = result.stdout
        print(f"Ping to {url} successful. Output: {output}") # Log successful ping
        return output

    except subprocess.TimeoutExpired:
        print(f"Ping to {url} timed out.") # Log timeout
        raise Exception("Ping timed out.")
    except subprocess.CalledProcessError as e:
        print(f"Ping to {url} failed with error: {e.stderr}") # Log error
        raise Exception(f"Ping failed: {e.stderr}")
    except Exception as e:
        print(f"Unexpected error during ping to {url}: {e}") # Log unexpected error
        raise


if __name__ == "__main__":
    # Set debug=False in production
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

