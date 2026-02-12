import urllib.parse
import re
import logging

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.WARNING)  # Or logging.INFO, logging.DEBUG, etc.

_DEFAULT_REDIRECT_URL = "/"  # Define a safe default redirect URL
_TARGET_URL_REGEX = re.compile(r"^https:\/\/example\.com\/.*$", re.IGNORECASE)  # Restrictive regex

def get_redirect_url(target_url: str) -> str:
    """
    Validates a target URL and returns it if it's safe for redirection.
    Otherwise, returns a default redirect URL.

    Args:
        target_url: The URL to validate.

    Returns:
        A safe URL for redirection.
    """

    if not target_url:
        logging.warning("Target URL is empty. Using default redirect.")
        return _DEFAULT_REDIRECT_URL

    try:
        # 1. Explicit URL Decoding
        try:
            decoded_url = urllib.parse.unquote(target_url)
        except UnicodeDecodeError:
            logging.warning(f"Invalid URL encoding: {target_url}. Using default redirect.")
            return _DEFAULT_REDIRECT_URL

        # 2. Canonicalization
        decoded_url = decoded_url.lower()
        if decoded_url.endswith('/'):
            decoded_url = decoded_url[:-1]

        # 3. URL Parsing and Validation
        try:
            parsed_url = urllib.parse.urlparse(decoded_url)

            # Check scheme (HTTPS only)
            if parsed_url.scheme != "https":
                logging.warning(f"Invalid scheme: {parsed_url.scheme}. HTTPS required. Using default redirect.")
                return _DEFAULT_REDIRECT_URL

            # Check netloc (domain) - This is already covered by the regex, but adding for extra safety
            # if parsed_url.netloc != "example.com":  # Removed as regex handles this better
            #    logging.warning(f"Invalid netloc: {parsed_url.netloc}. Allowed: example.com. Using default redirect.")
            #    return _DEFAULT_REDIRECT_URL

            # Check path (optional, but good practice)
            # Example: Ensure path starts with a specific prefix
            # if not parsed_url.path.startswith("/safe/path/"):
            #    logging.warning(f"Invalid path: {parsed_url.path}. Path must start with /safe/path/. Using default redirect.")
            #    return _DEFAULT_REDIRECT_URL

        except Exception as e:
            logging.warning(f"Error parsing URL: {e}. Using default redirect.")
            return _DEFAULT_REDIRECT_URL

        # 4. Regex Matching (after decoding and canonicalization)
        if _TARGET_URL_REGEX.match(decoded_url):
            # 5. Re-encoding (only the path and query)
            # Re-encode the path and query components to ensure proper formatting
            encoded_path = urllib.parse.quote(parsed_url.path)
            encoded_query = urllib.parse.quote(parsed_url.query)

            # Reconstruct the URL with encoded components
            reencoded_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                encoded_path,
                parsed_url.params,
                encoded_query,
                parsed_url.fragment
            ))

            logging.info(f"Redirecting to: {reencoded_url}")
            return reencoded_url
        else:
            logging.warning(f"Target URL {decoded_url} does not match allowed pattern. Using default redirect.")
            return _DEFAULT_REDIRECT_URL

    except Exception as e:
        logging.exception(f"Unexpected error during URL validation: {e}. Using default redirect.")
        return _DEFAULT_REDIRECT_URL

    # Consider a dedicated URL validation library like `validators` or `urlparse4`
    # for more comprehensive validation and handling of edge cases.


# Example Usage (Flask)
if __name__ == '__main__':
    from flask import Flask, request, redirect, abort

    app = Flask(__name__)

    @app.route('/redirect')
    def do_redirect():
        target = request.args.get('target')
        if not target:
            abort(400)  # Bad Request
        safe_url = get_redirect_url(target)
        return redirect(safe_url)

    # Example calls:
    # /redirect?target=https://example.com/safe/path
    # /redirect?target=https://example.com/safe/path?query=value
    # /redirect?target=https://attacker.com  (will redirect to default)

    app.run(debug=True)

