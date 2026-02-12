import requests
from flask import Flask, request, abort
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_SCHEMES = ["http", "https"]  # Whitelist allowed schemes
ALLOWED_HOSTS = [] # Whitelist allowed hosts.  Leave empty to allow all.  Example: ["example.com", "safe-domain.net"]

@app.route("/full_ssrf")
def full_ssrf():
    """
    Get the URL from the request, validate it, make a request to the URL, and return the response.

    This function implements several security measures to prevent Server-Side Request Forgery (SSRF) attacks:

    1.  **URL Parsing and Validation:**  The input URL is parsed using `urllib.parse.urlparse` to extract its components (scheme, hostname, etc.).  This allows for easier validation.

    2.  **Scheme Whitelisting:**  The URL scheme (e.g., "http", "https") is checked against a whitelist (`ALLOWED_SCHEMES`).  Only allowed schemes are processed.  This prevents attackers from using schemes like `file://`, `gopher://`, or `ftp://` to access internal resources or execute arbitrary commands.

    3.  **Hostname Whitelisting (Optional):** The hostname is checked against a whitelist (`ALLOWED_HOSTS`). If `ALLOWED_HOSTS` is not empty, only requests to whitelisted hosts are allowed. This provides an additional layer of security by restricting requests to known and trusted domains.  If `ALLOWED_HOSTS` is empty, all hosts are allowed (after scheme validation).

    4.  **Error Handling:**  The code includes `try...except` blocks to handle potential exceptions during the request process (e.g., `requests.exceptions.RequestException`).  This prevents the application from crashing and provides a more graceful response to the user.

    5.  **Timeout:** A timeout is set for the request to prevent indefinite hanging.

    6.  **User-Agent:** Setting a custom User-Agent can help with logging and identifying legitimate requests.

    7.  **No Redirects:**  `allow_redirects=False` prevents the server from following redirects, which could lead to unexpected destinations.

    8.  **Input Sanitization (Important Consideration):**  While this example focuses on URL validation, it's crucial to sanitize any other input used in the application to prevent other types of attacks (e.g., Cross-Site Scripting (XSS), SQL Injection).

    Args:
        None (takes URL from request parameter)

    Returns:
        The response from the requested URL, or an error message if the request fails or is invalid.
    """
    target_url = request.args.get("url")

    if not target_url:
        return "Error: URL parameter is missing.", 400

    try:
        parsed_url = urlparse(target_url)

        # Scheme Whitelisting
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            return f"Error: Invalid scheme. Allowed schemes are: {', '.join(ALLOWED_SCHEMES)}", 400

        # Hostname Whitelisting (Optional)
        if ALLOWED_HOSTS and parsed_url.hostname not in ALLOWED_HOSTS:
            return f"Error: Invalid hostname. Allowed hosts are: {', '.join(ALLOWED_HOSTS)}", 400

        # Make the request with security measures
        headers = {'User-Agent': 'Secure-SSRF-App'}  # Set a User-Agent
        response = requests.get(target_url, headers=headers, timeout=5, allow_redirects=False) # Set timeout and disable redirects
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        return response.text, response.status_code

    except requests.exceptions.RequestException as e:
        return f"Error: Request failed: {str(e)}", 500
    except ValueError as e:
        return f"Error: Invalid URL: {str(e)}", 400
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True)

