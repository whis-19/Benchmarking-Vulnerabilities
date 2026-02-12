from flask import Flask, redirect, request
import re
from urllib.parse import urlparse, quote
import idna
import unicodedata
import logging
import urllib.error

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.ERROR)

# Define a list of allowed domains.  This should be as restrictive as possible.
# Use wildcard subdomains carefully.  For example, "*.example.com" allows any subdomain of example.com.
ALLOWED_DOMAINS = [
    "example.com",  # Replace with your allowed domains
    "www.example.com",
    "subdomain.example.com",
    "*.allowed.com" # Example of wildcard subdomain
]

def is_domain_allowed(hostname, allowed_domains):
    """Checks if a hostname is allowed, supporting wildcard subdomains."""
    hostname = hostname.lower()
    for domain in allowed_domains:
        domain = domain.lower()
        if domain.startswith("*."):
            # Wildcard domain: check if hostname ends with the domain part AND
            # that the part before the domain is a valid subdomain part.
            pattern = re.compile(r"^[a-z0-9.-]*" + re.escape(domain[1:]) + "$")
            if pattern.match(hostname):
                return True
        elif hostname == domain:
            return True
    return False

def encode_url(url):
    """Whitelists allowed characters and encodes everything else."""
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;="
    encoded_url = "".join(c if c in allowed_chars else quote(c) for c in url)
    return encoded_url


@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request, check if it contains a valid domain, and
    then redirect to the target URL.  Implements robust security checks to prevent open redirects.
    '''
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided.", 400  # Bad Request

    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname

        if not hostname:
            return "Error: Invalid URL.", 400

        try:
            hostname = unicodedata.normalize('NFKC', hostname)  # Normalize Unicode
            hostname = idna.encode(hostname).decode('ascii')
        except idna.IDNAError as e:
            logging.error(f"IDNA error: {e}, URL: {target}, IP: {request.remote_addr}", exc_info=True)
            return "Error: Invalid domain (IDNA).", 400

        if not is_domain_allowed(hostname, ALLOWED_DOMAINS):
            return "Error: Invalid domain.", 400

        # Further validation: Ensure the scheme is either http or https.
        if parsed_url.scheme not in ("http", "https"):
            return "Error: Invalid scheme. Only HTTP and HTTPS are allowed.", 400

        # Remove fragment identifier
        sanitized_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        if parsed_url.query:
            sanitized_url += "?" + parsed_url.query

        # Comprehensive URL encoding using whitelisting
        sanitized_url = encode_url(sanitized_url)

        # Redirect to the sanitized URL.  Use a 302 redirect for temporary redirects.
        # Consider redirecting to a safe page on your own domain instead of an open redirect.
        # return redirect(sanitized_url, code=302)

        # Example of redirecting to a safe page:
        safe_redirect_url = "/safe_redirect?url=" + quote(sanitized_url)  # Encode for the safe redirect URL
        return redirect(safe_redirect_url, code=302)


    except urllib.error.URLError as e:
        logging.error(f"URL error: {e}, URL: {target}, IP: {request.remote_addr}", exc_info=True)
        return "Error: Network error.", 400
    except ValueError as e:
        logging.error(f"Value error: {e}, URL: {target}, IP: {request.remote_addr}", exc_info=True)
        return "Error: Invalid URL format.", 400
    except Exception as e:
        logging.exception(f"Unexpected error processing URL: {e}, URL: {target}, IP: {request.remote_addr}")
        return "Error: Internal server error.", 500


@app.route('/safe_redirect')
def safe_redirect():
    """Displays a safe redirect page with a link to the target URL."""
    url = request.args.get('url')
    if not url:
        return "Error: No URL provided.", 400
    return f"""
    <html>
    <body>
    <p>You are being redirected to: <a href="{url}">{url}</a></p>
    <p>Click the link above to continue.</p>
    </body>
    </html>
    """


if __name__ == '__main__':
    app.run(debug=True)

