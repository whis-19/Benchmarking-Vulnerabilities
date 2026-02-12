from flask import Flask, request, redirect, abort
from urllib.parse import urlparse
import time

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 6

ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_HOSTS = ['example.com', 'www.example.com']  # Add your allowed hosts here
MAX_REQUESTS_PER_MINUTE = 10  # Guideline 9
request_counts = {}


def is_safe_url(target, strict_host_validation=True):
    """
    Checks if the target URL is safe to redirect to.

    Args:
        target: The URL to redirect to.
        strict_host_validation: If True, only exact matches to ALLOWED_HOSTS are allowed.
                                 If False, subdomains are also allowed.  Use with caution.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        parsed_url = urlparse(target)
        if parsed_url.scheme not in ALLOWED_SCHEMES:
            return False

        netloc = parsed_url.netloc.lower()  # Convert to lowercase for case-insensitive comparison

        for allowed_host in ALLOWED_HOSTS:
            allowed_host_lower = allowed_host.lower() # Convert to lowercase for case-insensitive comparison
            if netloc == allowed_host_lower:
                return True
            elif not strict_host_validation and netloc.endswith("." + allowed_host_lower):
                return True

        return False
    except Exception:
        return False  # Handle parsing errors as unsafe


def rate_limit():
    """
    Implements a *very basic* rate limiter.  **DO NOT USE THIS IN PRODUCTION.**

    This implementation has significant limitations:
    - In-memory storage:  Rate limiting is only effective for a single instance.
    - IP-based:  Easily spoofed and affects users behind NAT.
    - Simple counting:  Susceptible to burst attacks.

    **For production, use a dedicated rate limiting library like Flask-Limiter
    or implement rate limiting using a persistent storage backend like Redis.**
    """
    client_ip = request.remote_addr
    now = time.time()
    if client_ip in request_counts:
        requests, last_request_time = request_counts[client_ip]
        if now - last_request_time < 60:  # Within the last minute
            if requests >= MAX_REQUESTS_PER_MINUTE:
                abort(429)  # Too Many Requests
            else:
                request_counts[client_ip] = (requests + 1, now)
        else:
            request_counts[client_ip] = (1, now)  # Reset count
    else:
        request_counts[client_ip] = (1, now)


@app.route('/')
def redirect_view():
    """
    Redirects the user to the next_url specified on the GET request,
    but only if it's a safe URL.
    """
    rate_limit()  # Guideline 9

    next_url = request.args.get('next_url')

    if not next_url:
        app.logger.warning("Missing next_url parameter from IP: %s", request.remote_addr)
        return "Missing next_url parameter", 400  # Bad Request

    MAX_URL_LENGTH = 2048  # Example maximum URL length
    if len(next_url) > MAX_URL_LENGTH:
        app.logger.warning("next_url exceeds maximum length (%d) from IP: %s", MAX_URL_LENGTH, request.remote_addr)
        return "URL too long", 400

    if is_safe_url(next_url):  # Guideline 1
        return redirect(next_url)
    else:
        app.logger.warning("Unsafe redirect attempted to: %s from IP: %s", next_url, request.remote_addr)
        return "Unsafe redirect target", 400  # Bad Request


# Example of setting a Content Security Policy (CSP)
@app.after_request
def add_csp_header(response):
    """
    Adds a Content Security Policy header to the response.

    CSP allows you to control the sources from which the browser is allowed to load resources.
    This significantly reduces the risk of Cross-Site Scripting (XSS) attacks.

    **IMPORTANT:** This is a starting point.  You *must* customize this based on your application's needs.

    Example CSP directives:
    - default-src:  Fallback for other directives.
    - script-src:  Allowed sources for JavaScript.  Use 'nonce-' or 'hash-' for inline scripts.
    - style-src:  Allowed sources for CSS.  Use 'nonce-' or 'hash-' for inline styles.
    - img-src:  Allowed sources for images.
    - font-src:  Allowed sources for fonts.
    - connect-src:  Allowed sources for AJAX/Fetch requests.
    - report-uri:  URL to which CSP violations are reported.

    Consider starting with a `Content-Security-Policy-Report-Only` header to test your policy
    without breaking functionality.  Monitor the reports and adjust the policy as needed.

    Example CSPs:

    # 1. Strict CSP (only allow resources from the same origin):
    #    csp = "default-src 'self';"

    # 2. More permissive CSP (allow scripts from a CDN):
    #    csp = "default-src 'self'; script-src 'self' https://cdn.example.com;"

    # 3. CSP with nonce for inline scripts (replace 'random_nonce' with a dynamically generated value):
    #    csp = "default-src 'self'; script-src 'self' 'nonce-random_nonce';"

    # 4. CSP with report-uri:
    #    csp = "default-src 'self'; report-uri /csp-report-endpoint;"

    """
    csp = "default-src 'self';"  # Start with a restrictive policy
    response.headers['Content-Security-Policy'] = csp
    return response


if __name__ == '__main__':
    app.run(debug=False)

