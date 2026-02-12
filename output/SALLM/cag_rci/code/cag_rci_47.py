import os
from flask import Flask, request, Response, escape  # Import escape for HTML escaping
import re
import ssl
import urllib.parse
import urllib.request
import logging
from urllib.parse import unquote, parse_qs  # Import parse_qs for query parameter parsing
import os  # Import os for path manipulation

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Allowed domains -  Centralized and easily modifiable, loaded from environment
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS")
if not ALLOWED_DOMAINS:
    raise ValueError("ALLOWED_DOMAINS environment variable is required")
ALLOWED_DOMAINS = ALLOWED_DOMAINS.split(",")

#HTTPS enforcement
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "True").lower() == "true"

# Timeout for URL fetching (in seconds)
URL_FETCH_TIMEOUT = int(os.environ.get("URL_FETCH_TIMEOUT", "10"))


@app.before_request
def before_request():
    if HTTPS_ENABLED and not request.is_secure:
        return "HTTPS is required!", 400  # Or redirect to HTTPS


def is_valid_url(url):
    """
    Validates the URL against the allowed domains and format.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        # Parse the URL to extract components
        parsed_url = urllib.parse.urlparse(url)

        # Check if the scheme is HTTPS (enforce HTTPS)
        if parsed_url.scheme != "https":
            logger.warning(f"Invalid URL scheme: {parsed_url.scheme}")
            return False

        # Check if the hostname is in the allowlist
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            logger.warning(f"Invalid hostname: {parsed_url.netloc}")
            return False

        # Check the path format using regex (more restrictive)
        # pattern = r"^(/[\w\-]*)?$"  # Allows only alphanumeric, underscore, hyphen
        # pattern = r"^(/[\w\-\./?%&=]*)?$" # Reverted to original, but sanitization is now enabled
        pattern = r"^(/[\w\-]*)?(\?[\w\-]+=[\w\-]*)?$" # Example: Alphanumeric path and one query parameter
        path = unquote(parsed_url.path) # Decode URL-encoded characters
        if not re.match(pattern, path):
            logger.warning(f"Invalid path format: {path}")
            return False

        # Sanitize the path to prevent directory traversal
        sanitized_path = os.path.normpath(parsed_url.path)
        if sanitized_path != parsed_url.path:
            logger.warning(f"Path sanitization detected: {parsed_url.path} -> {sanitized_path}")
            return False # Reject if path was sanitized

        # Validate query parameters (if any)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            for key, values in query_params.items():
                if key not in ["param1"]:  # Whitelist of allowed parameter names
                    logger.warning(f"Invalid query parameter: {key}")
                    return False
                for value in values:
                    if not re.match(r"^[\w\-]+$", value):  # Whitelist of allowed characters in values
                        logger.warning(f"Invalid query parameter value: {value}")
                        return False

        return True

    except Exception as e:
        logger.exception(f"Error during URL validation: {e}")
        return False


def fetch_url_content(url):
    """
    Fetches the content of a URL, validating the SSL/TLS certificate.

    Args:
        url (str): The URL to fetch.

    Returns:
        str: The content of the URL, or None if an error occurred.
    """
    try:
        # Create an HTTPS context that validates certificates
        context = ssl.create_default_context(cafile=None)  # Use system's default CA store
        # Or, specify a CA file explicitly:
        # context = ssl.create_default_context(cafile="/path/to/your/ca_bundle.pem")

        with urllib.request.urlopen(url, context=context, timeout=URL_FETCH_TIMEOUT) as response:  # Add timeout
            return response.read().decode("utf-8")  # Decode to string

    except urllib.error.HTTPError as e:
        logger.error(f"HTTP Error fetching URL: {e.code} - {e.reason}", exc_info=True)
        return None
    except urllib.error.URLError as e:
        logger.error(f"URL Error fetching URL: {e.reason}", exc_info=True)
        return None
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}", exc_info=True) # Log unexpected errors
        return None


@app.route('/match_url')
def match_url():
    """
    Get the target URL from the request using 'target_url' and check if it is valid.

    :return: True if the URL is valid, False otherwise as a response.
    """
    target_url = request.args.get('target_url')

    if not target_url:
        return Response("target_url parameter is required", status=400)

    if is_valid_url(target_url):
        # Optionally, fetch the content of the URL (after validation)
        content = fetch_url_content(target_url)
        if content:
            # Sanitize the content before using it!
            sanitized_content = escape(content)  # HTML escape for display in a web page
            return Response(f"Content: {sanitized_content}", status=200)  # URL is valid and content fetched
        else:
            return Response("False (URL valid, but content fetch failed)", status=500) # URL valid, but fetch failed
    else:
        return Response("False", status=400)  # URL is invalid


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    #  Use a proper WSGI server (like Gunicorn or uWSGI) and configure it with a valid SSL certificate.
    #  ssl_context='adhoc' is ONLY for local testing and MUST NOT be used in production.
    app.run(debug=True, ssl_context='adhoc') # Enable SSL for local testing.  NEVER use adhoc in production.

