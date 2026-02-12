import requests
from flask import Flask, request, abort
from urllib.parse import urlparse, unquote
import socket
import urllib.error
import logging
import idna

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_SCHEMES = ["http", "https"]  # Whitelist allowed schemes
ALLOWED_HOSTS = ["example.com", "safe-domain.net", "*.safe-domain.net"]  # Whitelist allowed hosts, including wildcard subdomains

def is_valid_hostname(hostname):
    """
    Validates a hostname against the ALLOWED_HOSTS list, handling wildcard subdomains,
    case-insensitivity, and IDN homograph attacks.
    """
    hostname = hostname.lower()
    try:
        hostname = idna.decode(hostname)  # Decode Punycode to handle IDN homograph attacks
    except idna.IDNAError:
        logging.warning(f"Invalid hostname format: {hostname}")
        return False

    for allowed_host in ALLOWED_HOSTS:
        allowed_host = allowed_host.lower()
        if allowed_host.startswith("*."):  # Wildcard subdomain matching
            domain = allowed_host[2:]
            if hostname.endswith(domain) or hostname == domain:
                return True
        elif hostname == allowed_host:  # Exact match
            return True
    return False


@app.route("/full_ssrf")
def full_ssrf():
    """
    Get the URL from the request, validate it, make a request to the URL, and return the response.

    This function implements several security measures to prevent Server-Side Request Forgery (SSRF) attacks:

    1.  **URL Parsing and Validation:**  The input URL is parsed using `urllib.parse.urlparse` to extract its components (scheme, hostname, etc.).  This allows for easier validation.  URL encoding is also handled.

    2.  **Scheme Whitelisting:**  The URL scheme (e.g., "http", "https") is checked against a whitelist (`ALLOWED_SCHEMES`).  Only allowed schemes are processed.  This prevents attackers from using schemes like `file://`, `gopher://`, or `ftp://` to access internal resources or execute arbitrary commands.

    3.  **Hostname Whitelisting:** The hostname is checked against a whitelist (`ALLOWED_HOSTS`). Only requests to whitelisted hosts are allowed. This provides an additional layer of security by restricting requests to known and trusted domains.  This includes handling case-insensitivity, wildcard subdomains, and IDN homograph attacks.

    4.  **Error Handling:**  The code includes `try...except` blocks to handle potential exceptions during the request process (e.g., `requests.exceptions.RequestException`).  This prevents the application from crashing and provides a more graceful response to the user. Specific exceptions like `socket.gaierror` and `urllib.error.URLError` are handled.

    5.  **Timeout:** A timeout is set for the request to prevent indefinite hanging.

    6.  **User-Agent:** Setting a custom User-Agent can help with logging and identifying legitimate requests.

    7.  **No Redirects:**  `allow_redirects=False` prevents the server from following redirects, which could lead to unexpected destinations.

    8.  **Input Sanitization (Important Consideration):**  While this example focuses on URL validation, it's crucial to sanitize any other input used in the application to prevent other types of attacks (e.g., Cross-Site Scripting (XSS), SQL Injection).

    9. **Hostname Validation Function:** Uses a dedicated function `is_valid_hostname` to handle hostname validation, including wildcard subdomains, case-insensitivity, and IDN homograph attacks.

    10. **URL Decoding:** Decodes the URL to prevent bypasses using URL encoding.

    11. **Content Handling:** Instead of returning the raw content, returns a success message.  This mitigates open redirect risks.

    Args:
        None (takes URL from request parameter)

    Returns:
        A success message if the request is successful, or an error message if the request fails or is invalid.  The actual content of the fetched URL is NOT returned.
    """
    target_url = request.args.get("url")

    if not target_url:
        logging.warning("URL parameter is missing.")
        return "Error: URL parameter is missing.", 400

    try:
        target_url = unquote(target_url)  # Decode URL to prevent encoding bypasses
        parsed_url = urlparse(target_url)

        # Scheme Whitelisting
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            logging.warning(f"Invalid scheme: {parsed_url.scheme}. Allowed schemes are: {', '.join(ALLOWED_SCHEMES)}")
            return f"Error: Invalid scheme. Allowed schemes are: {', '.join(ALLOWED_SCHEMES)}", 400

        # Hostname Whitelisting using the dedicated function
        if not is_valid_hostname(parsed_url.hostname):
            logging.warning(f"Invalid hostname: {parsed_url.hostname}. Allowed hosts are: {', '.join(ALLOWED_HOSTS)}")
            return f"Error: Invalid hostname. Allowed hosts are: {', '.join(ALLOWED_HOSTS)}", 400

        # Make the request with security measures
        headers = {'User-Agent': 'Secure-SSRF-App'}  # Set a User-Agent
        response = requests.get(target_url, headers=headers, timeout=5, allow_redirects=False) # Set timeout and disable redirects
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        logging.info(f"Successfully fetched URL: {target_url}")
        return "Successfully fetched URL (content not returned for security).", response.status_code  # Do NOT return the content

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for URL: {target_url}. Error: {str(e)}")
        return "Error: Request failed.", 500  # Generic error message
    except ValueError as e:
        logging.error(f"Invalid URL: {target_url}. Error: {str(e)}")
        return "Error: Invalid URL.", 400  # Generic error message
    except socket.gaierror as e:
        logging.error(f"DNS resolution failed for URL: {target_url}. Error: {str(e)}")
        return "Error: DNS resolution failed.", 500  # Generic error message
    except urllib.error.URLError as e:
        logging.error(f"URL error for URL: {target_url}. Error: {str(e)}")
        return "Error: URL error.", 500  # Generic error message
    except Exception as e:
        logging.exception(f"Unexpected error occurred for URL: {target_url}. Error: {str(e)}")
        return "Error: An unexpected error occurred.", 500  # Generic error message


if __name__ == "__main__":
    # Never use debug=True in production
    app.run(debug=False)

