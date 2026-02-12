import re
import urllib.parse
import logging
import datetime
from typing import Optional

# Configure logging (basic example)
logging.basicConfig(level=logging.INFO)

# Default redirect URL (MUST be safe and under your control)
_DEFAULT_REDIRECT_URL = "https://example.com/safe-redirect"

# Strict regex for allowed target URLs (ALLOWLIST approach is crucial)
# Example: Only allow URLs starting with https://example.com/ or https://example.org/
_TARGET_URL_REGEX = re.compile(r"^(https://(example\.com|example\.org)/.*)$")

def get_redirect_url(target_url: str, request: Optional[object] = None) -> str:
    """
    Validates a target URL and returns it if it's safe, otherwise returns the default redirect URL.

    Args:
        target_url: The URL to redirect to.
        request: (Optional) The Flask request object (or similar) for logging context.

    Returns:
        A safe URL to redirect to.
    """

    if not target_url:
        logging.warning(f"Empty target URL provided. Redirecting to default. User IP: {getattr(request, 'remote_addr', 'N/A')}, Headers: {getattr(request, 'headers', 'N/A')}, Timestamp: {datetime.datetime.now()}")
        return _DEFAULT_REDIRECT_URL

    try:
        # 1. Decode the URL to handle encoding bypasses
        decoded_url = urllib.parse.unquote(target_url)

        # 2. Parse the decoded URL
        parsed_url = urllib.parse.urlparse(decoded_url)

        # 3. Scheme validation (only allow HTTPS)
        if parsed_url.scheme != "https":
            logging.warning(f"Invalid scheme: {parsed_url.scheme}. Only HTTPS allowed. Target URL: {target_url}, User IP: {getattr(request, 'remote_addr', 'N/A')}, Headers: {getattr(request, 'headers', 'N/A')}, Timestamp: {datetime.datetime.now()}")
            return _DEFAULT_REDIRECT_URL

        # 4. Host validation (against the regex)
        if not _TARGET_URL_REGEX.match(decoded_url):  # Use decoded_url for regex matching
            logging.warning(f"Invalid target URL: {decoded_url}. Does not match allowlist regex. Target URL: {target_url}, User IP: {getattr(request, 'remote_addr', 'N/A')}, Headers: {getattr(request, 'headers', 'N/A')}, Timestamp: {datetime.datetime.now()}")
            return _DEFAULT_REDIRECT_URL

        # 5.  Re-encode specific parts of the URL (e.g., query parameters)
        #     This is a simplified example.  More sophisticated encoding might be needed.
        #     Consider using a library like `urllib.parse.quote` for more robust encoding.
        #     This step prevents double-encoding attacks and ensures proper formatting.
        encoded_path = urllib.parse.quote(parsed_url.path)
        encoded_query = urllib.parse.quote(parsed_url.query)
        reconstructed_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, encoded_path, parsed_url.params, encoded_query, parsed_url.fragment))

        # Log successful redirect (optional, but recommended)
        logging.info(f"Redirecting to: {reconstructed_url}. User IP: {getattr(request, 'remote_addr', 'N/A')}, Headers: {getattr(request, 'headers', 'N/A')}, Timestamp: {datetime.datetime.now()}")

        return reconstructed_url  # Return the re-encoded URL

    except Exception as e:
        logging.error(f"Error parsing URL: {e}. Target URL: {target_url}, User IP: {getattr(request, 'remote_addr', 'N/A')}, Headers: {getattr(request, 'headers', 'N/A')}, Timestamp: {datetime.datetime.now()}")
        return _DEFAULT_REDIRECT_URL


# Example usage with Flask (assuming you have Flask installed)
if __name__ == '__main__':
    from flask import Flask, request, redirect

    app = Flask(__name__)

    @app.route('/redirect')
    def redirect_route():
        target = request.args.get('target')
        safe_url = get_redirect_url(target, request)  # Pass the request object
        return redirect(safe_url)

    # Example of a vulnerable route (DO NOT USE IN PRODUCTION)
    @app.route('/unsafe_redirect')
    def unsafe_redirect_route():
        target = request.args.get('target')
        return redirect(target) #VULNERABLE!

    app.run(debug=True)

# Key points for using this code in a real application:
# 1.  **Strict ALLOWLIST Regex:**  The `_TARGET_URL_REGEX` is the most critical part.  It *must* be carefully crafted to only allow URLs that are explicitly trusted.  Avoid overly broad regexes.  Consider using a configuration file to manage the allowed domains.
# 2.  **Subdomain Takeover Prevention:**  Be extremely careful with subdomain wildcards in the regex.  Ensure that you control all subdomains that are allowed.  Regularly audit your DNS records to prevent subdomain takeovers.
# 3.  **Referer Header is Unreliable:**  Do not rely on the `Referer` header for security.  It can be easily spoofed.
# 4.  **Logging:**  Implement comprehensive logging to track redirect attempts, including invalid URLs, user IP addresses, and timestamps.  This will help you identify and respond to potential attacks.  For example:
#

