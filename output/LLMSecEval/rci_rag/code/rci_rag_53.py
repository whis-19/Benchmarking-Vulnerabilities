import re
import urllib.parse
import logging
from flask import Flask, request, redirect, make_response
import tldextract  # Import tldextract

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Securely define the allowed target pattern.  Escape the '.'
# Consider allowing underscores if needed: ^[a-zA-Z0-9\-_]+\.
# ALLOWED_TARGET_PATTERN = r"^[a-zA-Z0-9\-]+\."  # Original regex - too restrictive

#  Using tldextract for more robust domain validation.  Requires `pip install tldextract`
#  This is *much* better than a regex for handling various domain formats.
#  However, tldextract relies on a list of TLDs that needs to be kept up-to-date.
#  Consider updating the TLD list regularly: tldextract.update()

ALLOWED_DOMAINS = ["example.com", "example.net"]  # Whitelist of allowed domains (optional, but recommended)


@app.route('/')
def index():
    # Example usage:  Simulate a request with a 'target' parameter.
    # In a real application, this would come from request.args.get('target')
    target = request.args.get('target')

    if target:
        return handle_redirection(target)
    else:
        return "No target specified."


def handle_redirection(target):
    """
    Handles redirection based on the 'target' parameter.

    Args:
        target: The value of the 'target' query parameter.

    Returns:
        A Flask redirect response.
    """

    try:
        # Properly construct the URL.  Use urllib.parse.urlparse to handle
        # different URL schemes and prevent injection vulnerabilities.
        parsed_url = urllib.parse.urlparse(target)

        # Check if a scheme is present. If not, add a safe default.
        if not parsed_url.scheme:
            target = "https://" + target  # Use https as the default
            parsed_url = urllib.parse.urlparse(target)  # Re-parse with the scheme

        # Extract domain information using tldextract
        extracted = tldextract.extract(parsed_url.netloc)

        # Validate the domain
        if not extracted.suffix or not extracted.domain:
            logging.info(f"Invalid domain format: {parsed_url.netloc}")
            return redirect("/")

        # Optional: Check against a whitelist of allowed domains
        # if parsed_url.netloc not in ALLOWED_DOMAINS:
        #     logging.info(f"Domain not in whitelist: {parsed_url.netloc}")
        #     return redirect("/")

        # Further validation:  Check for suspicious characters in subdomain, domain, and suffix
        if not re.match(r"^[a-zA-Z0-9\-.]*$", extracted.subdomain + extracted.domain + extracted.suffix):
            logging.info(f"Suspicious characters in domain parts: {extracted.subdomain + extracted.domain + extracted.suffix}")
            return redirect("/")

        # Create a redirect response.
        response = make_response(redirect(target, code=302))

        # Set security headers (example).  Crucially, set HttpOnly on the session cookie.
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Assuming you have a session cookie named 'session'
        # This is just an example, adapt to your actual session management.
        if 'session' in request.cookies:
            response.set_cookie('session', request.cookies.get('session'), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes are important

        # Content Security Policy (CSP) - adjust as needed for your application
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' https://cdn.example.com; img-src 'self' data: https://cdn.example.com"

        # Subresource Integrity (SRI) - Example (replace with actual SRI hashes)
        # response.headers['Link'] = '<https://example.com/style.css>; rel=preload; as=style; integrity="sha384-EXAMPLEHASH"; crossorigin="anonymous"'

        return response

    except Exception as e:
        logging.error(f"Error processing target: {e}")
        return redirect("/")


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

