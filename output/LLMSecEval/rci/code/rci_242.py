import subprocess
import functools
from flask import Flask, request, jsonify
import urllib.parse
import socket
import logging
import idna
import ipaddress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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
# 12. Handle Punycode domains.
# 13. Mitigate TOCTOU vulnerabilities in DNS resolution.
# 14. Implement IPv6 support.

ALLOWED_DOMAINS = ["google.com", "example.com"]  # Replace with your allowed domains

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust as needed
)


def validate_url(url):
    """
    Validates the URL to prevent command injection and SSRF.
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

        hostname = parsed_url.hostname
        try:
            hostname = idna.decode(hostname)
        except idna.IDNAError:
            logging.warning(f"Invalid Punycode hostname: {parsed_url.hostname}")
            return None

        # Whitelist allowed domains
        if hostname not in ALLOWED_DOMAINS:
            # Check if the hostname ends with an allowed domain (for subdomains)
            domain_allowed = False
            for domain in ALLOWED_DOMAINS:
                if hostname.endswith("." + domain) or hostname == domain:
                    domain_allowed = True
                    break
            if not domain_allowed:
                logging.warning(f"Hostname not in allowed domains: {hostname}")
                return None

        # Block private IP addresses (SSRF protection)
        if hostname in ("127.0.0.1", "localhost"):
            logging.warning("Blocked access to localhost")
            return None

        # Try to resolve the hostname to an IP address and block private IP ranges
        try:
            ip_address_str = socket.gethostbyname(hostname)
            ip_address = ipaddress.ip_address(ip_address_str)

            if ip_address.is_private:
                logging.warning(f"Blocked access to private IP range: {ip_address}")
                return None
        except socket.gaierror:
            # Handle DNS resolution errors (e.g., invalid domain)
            logging.warning(f"DNS resolution error for hostname: {hostname}")
            return None
        except ValueError:
            logging.warning(f"Invalid IP address: {ip_address_str}")
            return None

        return url

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
@limiter.limit("5/minute")  # Example rate limit: 5 requests per minute
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
        logging.info(f"Ping successful for URL: {url}")
        return output
    except subprocess.TimeoutExpired:
        logging.warning(f"Ping timed out for URL: {url}")
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        logging.error(f"Ping failed for URL: {url} with error: {e.stderr}")
        return "Ping failed." # Generic error message
    except Exception as e:
        logging.exception(f"An unexpected error occurred during ping for URL: {url}")
        return "An unexpected error occurred." # Generic error message


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    # It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

