import cgi
import os
from urllib.parse import urlparse, quote
import idna  # For IDN handling (install with pip install idna)

ALLOWED_DOMAINS = ['example.com', 'www.example.com', 'secure.example.net']  # Whitelist

def is_safe_url(target):
    """
    Checks if a target URL is safe to redirect to.  This is a crucial security measure
    to prevent open redirect vulnerabilities.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    if not target:
        return False

    try:
        url = urlparse(target)
    except:
        return False  # Handle parsing errors

    # Check if the scheme is allowed (e.g., http, https).  Crucially important.
    allowed_schemes = ['http', 'https']
    if url.scheme not in allowed_schemes:
        return False

    # Domain validation with IDN handling
    try:
        netloc = url.netloc.encode('idna').decode('ascii')  # Convert to Punycode
    except UnicodeError:
        return False  # Invalid domain name

    if netloc not in ALLOWED_DOMAINS:
        return False

    # Optional: Check port (if needed)
    # if url.port not in [80, 443]:
    #     return False

    # Optional: Check path (if needed)
    # if not url.path.startswith('/allowed/path'):
    #     return False

    return True


def redirect_handler(environ):
    """
    Handles the redirect logic based on the 'target' query parameter.

    Args:
        environ: The WSGI environment dictionary.

    Returns:
        A WSGI response (a tuple of (status, headers, body)).
    """

    form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ, keep_blank_values=True)
    target = form.getvalue('target', '')

    # REMOVE THE REGEX CHECK - IT'S HARMFUL

    if target and is_safe_url(target):
        # Redirect to the target URL (if it's safe).
        status = '302 Found'
        safe_target = quote(target)  # URL-encode the target
        headers = [('Location', safe_target)]
        body = b''  # Empty body for redirects
    else:
        # Redirect to the root of the site (if the target is invalid or unsafe).
        status = '302 Found'
        headers = [('Location', '/')]  # Redirect to the root
        body = b''

    return status, headers, body


# Example WSGI application (for demonstration purposes)
def application(environ, start_response):
    """
    A simple WSGI application that uses the redirect_handler.
    """
    status, headers, body = redirect_handler(environ)
    start_response(status, headers)
    return [body]


if __name__ == '__main__':
    # Example usage (using a simple WSGI server)
    from wsgiref.simple_server import make_server

    # Set the application domain (replace with your actual domain)
    os.environ['APP_DOMAIN'] = 'example.com'

    httpd = make_server('', 8000, application)
    print("Serving on port 8000...")
    httpd.serve_forever()

