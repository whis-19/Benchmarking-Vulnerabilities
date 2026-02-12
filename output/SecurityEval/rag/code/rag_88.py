from flask import Flask, request, redirect, make_response
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 6

# Rate limiting (Guideline 9 - rudimentary example)
REQUEST_LIMIT = 10
request_counts = {}

ALLOWED_SCHEMES = ['http', 'https']  # Stringent allowlist for schemes (Guideline 4)
ALLOWED_HOSTS = ['example.com', 'safe-domain.net'] # Stringent allowlist for hosts (Guideline 4)

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  Validates scheme and hostname.
    Handles arbitrary subdomain sequences correctly.
    """
    try:
        parsed_url = urlparse(target) # Guideline 2: Parse URL before checking host
        
        # Check scheme
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            return False

        # Check hostname against allowlist, handling subdomains
        if parsed_url.hostname:
            hostname = parsed_url.hostname.lower()
            
            # Check for exact match or subdomain match
            is_allowed = False
            for allowed_host in ALLOWED_HOSTS:
                if hostname == allowed_host or hostname.endswith("." + allowed_host):
                    is_allowed = True
                    break
            if not is_allowed:
                return False
        else:
            return False # Hostname must be present

        return True
    except Exception:
        return False  # Handle parsing errors as unsafe

def rate_limit(ip_address):
    """Rudimentary rate limiting."""
    if ip_address not in request_counts:
        request_counts[ip_address] = 0
    
    request_counts[ip_address] += 1
    
    if request_counts[ip_address] > REQUEST_LIMIT:
        return False
    return True

@app.route('/')
def safe_redirect():
    """
    Redirects the user to the next_url specified on the GET request,
    but only if it's a safe URL.
    """
    next_url = request.args.get('next_url')

    if not next_url:
        return "Missing next_url parameter", 400

    # Validate request data (Guideline 5) - basic example
    if not isinstance(next_url, str):
        return "Invalid next_url format", 400

    # Rate limiting (Guideline 9)
    client_ip = request.remote_addr
    if not rate_limit(client_ip):
        return "Rate limit exceeded", 429

    if is_safe_url(next_url):
        response = make_response(redirect(next_url))
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Guideline 7
        return response
    else:
        return "Unsafe URL provided", 400

# Example of a route that should use GET (Guideline 10 - example)
@app.route('/change_state', methods=['GET'])
def change_state():
    """This route should use GET because it triggers a state change."""
    # Perform state change logic here
    return "State changed successfully", 200

if __name__ == '__main__':
    #  Use a secure WSGI server in production (e.g., gunicorn, uWSGI)
    #  and configure HTTPS.  This is a development server only.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

