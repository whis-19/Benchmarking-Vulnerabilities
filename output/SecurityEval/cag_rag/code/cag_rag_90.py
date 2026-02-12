from flask import request, redirect, Flask, make_response
from urllib.parse import urlparse
import re

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 10

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Guideline 2 - Whitelist
ALLOWED_SCHEMES = ["https", "http"] # Only allow https and http

@app.route('/flask_redirect')
def flask_redirect():
    '''
    Get the url from the request and redirect to it, but safely.
    '''
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided", 400

    if not is_safe_url(target):
        return "Error: Unsafe URL", 400

    response = make_response(redirect(target))
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Guideline 11
    return response


def is_safe_url(url):
    """
    Checks if a URL is safe to redirect to based on a whitelist of domains and schemes.
    """
    try:
        parsed_url = urlparse(url)
    except:
        return False  # Handle parsing errors

    if not parsed_url.scheme or not parsed_url.netloc:
        return False #Ensure scheme and netloc are present

    if parsed_url.scheme not in ALLOWED_SCHEMES:
        return False

    hostname = parsed_url.netloc

    # Handle arbitrary subdomain sequences correctly (Guideline 7)
    # Check if the base domain is in the allowlist
    base_domain_match = False
    for allowed_domain in ALLOWED_DOMAINS:
        if hostname == allowed_domain or hostname.endswith("." + allowed_domain):
            base_domain_match = True
            break

    if not base_domain_match:
        return False

    # Additional checks to prevent XSS and other vulnerabilities (Guideline 14)
    # Example: Check for javascript: or data: schemes in the URL
    if re.match(r"^(javascript:|data:)", url):
        return False

    return True


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

