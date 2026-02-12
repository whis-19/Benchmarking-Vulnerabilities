from flask import request, Response, Flask, redirect
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 8

ALLOWED_DOMAINS = {'example.com', 'safe-domain.net'}  # Guideline 2: Whitelist of allowed domains

def is_safe_url(target):
    """
    Checks if the target URL is safe for redirection.

    This function validates the target URL against a whitelist of allowed domains
    to prevent open redirect vulnerabilities.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    if not target:
        return False

    try:
        parsed_url = urlparse(target)
        # Check if netloc is empty or None
        if not parsed_url.netloc:
            # Relative URL, consider it safe if it doesn't start with //
            return not target.startswith('//')
        
        # Check if the scheme is allowed (HTTPS is preferred)
        if parsed_url.scheme not in ('http', 'https'):
            return False

        # Check if the domain is in the allowlist
        hostname = parsed_url.netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]  # Remove port if present
        return hostname in ALLOWED_DOMAINS
    except Exception:
        # Handle parsing errors (e.g., invalid URL)
        return False


@app.route('/set_location_header')
def set_location_header():
    """
    Gets the "next" value from the request and sets the location header for redirecting to the value of "next".
    Validates the URL against a whitelist to prevent open redirect vulnerabilities.
    """
    next_url = request.args.get('next')

    if next_url and is_safe_url(next_url):
        response = redirect(next_url, code=302)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Guideline 9
        return response
    else:
        # Handle the case where 'next' is missing or unsafe.  Crucially, do NOT redirect.
        return "Invalid or missing 'next' parameter.", 400  # Return an error


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS.  'adhoc' is for testing only.  Use real certificates in production. Guideline 3 & 4

