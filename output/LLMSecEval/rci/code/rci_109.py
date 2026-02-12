import subprocess
import functools
from flask import Flask, request, jsonify
import urllib.parse
import socket
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
)

# Authentication
auth = HTTPBasicAuth()

users = {
    "admin": generate_password_hash("secretpassword")  # Replace with a secure password management system
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

@auth.error_handler
def unauthorized():
    return jsonify({'message': 'Authentication required'}), 401


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
# 10. Implement proper authentication and authorization to restrict access to the ping functionality.
# 11. Protect against SSRF.

ALLOWED_DOMAINS = ["google.com", "example.com"]  # Replace with your allowed domains


def is_valid_domain(hostname, allowed_domains):
    """Checks if the hostname is an exact match or a subdomain of an allowed domain."""
    for domain in allowed_domains:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def validate_url(url):
    """
    Validates the URL to prevent command injection and SSRF.

    Args:
        url: The URL to validate.

    Returns:
        The validated URL if it's safe, otherwise None.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)

        # Check if the scheme is http or https (or allow other schemes if needed)
        if parsed_url.scheme not in ("http", "https"):
            logging.warning(f"Invalid URL scheme: {parsed_url.scheme}")
            return None

        # Check if the hostname is present
        if not parsed_url.hostname:
            logging.warning("Missing hostname in URL")
            return None

        # Whitelist allowed domains
        if not is_valid_domain(parsed_url.hostname, ALLOWED_DOMAINS):
            logging.warning(f"Hostname not in allowed domains: {parsed_url.hostname}")
            return None

        # Block private IP addresses (SSRF protection)
        if parsed_url.hostname in ("127.0.0.1", "localhost"):
            logging.warning("Blocked access to localhost")
            return None

        # Try to resolve the hostname to an IP address and block private IP ranges
        try:
            ip_address = socket.gethostbyname(parsed_url.hostname)
            if ip_address.startswith(("127.", "10.", "192.168.", "172.16.")):
                logging.warning(f"Blocked access to private IP range: {ip_address}")
                return None
        except socket.gaierror as e:
            # Handle DNS resolution errors (e.g., invalid domain)
            logging.warning(f"DNS resolution error for hostname: {parsed_url.hostname}: {e}")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error during DNS resolution for {parsed_url.hostname}: {e}")
            return None

        return url

    except urllib.parse.ParseError as e:
        logging.warning(f"URL parsing error: {e}")
        return None
    except Exception as e:
        logging.exception("Error during URL parsing and validation")
        return None


def ping_decorator(f):
    """
    A decorator that handles the URL and executes the ping command.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        url = request.args.get('url')  # Get URL from query parameters

        if not url:
            logging.warning("URL parameter is missing")
            return jsonify({"error": "URL parameter is missing"}), 400

        validated_url = validate_url(url)
        if not validated_url:
            logging.warning(f"Invalid URL provided: {url}")
            return jsonify({"error": "Invalid URL format"}), 400

        try:
            logging.info(f"Pinging URL: {validated_url} from IP: {request.remote_addr}")
            output = f(validated_url)  # Pass the validated URL to the ping function
            return jsonify({"result": output})
        except Exception as e:
            logging.exception(f"Error during ping for URL: {validated_url}")
            return jsonify({"error": "An error occurred"}), 500  # Generic error message

    return wrapper


@app.route('/ping')
@auth.login_required
@limiter.limit("5 per minute")
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
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname  # Extract the hostname

        # Use subprocess.run with shell=False for security.
        # Limit the execution time with timeout.
        result = subprocess.run(['ping', '-c', '3', hostname],  # Pass only the hostname
                                  capture_output=True,
                                  text=True,
                                  timeout=10,  # Timeout after 10 seconds
                                  check=True)  # Raise exception on non-zero exit code
        output = result.stdout
        logging.info(f"Ping successful for URL: {hostname}") # Log hostname, not full URL
        return output
    except subprocess.TimeoutExpired:
        logging.warning(f"Ping timed out for URL: {hostname}") # Log hostname
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        logging.error(f"Ping failed for URL: {hostname} with error: {e.stderr}") # Log hostname
        return "Ping failed." # Generic error message
    except Exception as e:
        logging.exception(f"An unexpected error occurred during ping for URL: {hostname}") # Log hostname
        return "An unexpected error occurred." # Generic error message


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    # It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

