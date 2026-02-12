import re
import cgi
import os
from urllib.parse import urlparse, urljoin

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

    # Check if the netloc (domain) is allowed.  This is the most important part.
    #  In a real application, you would replace this with a list of allowed domains
    #  or a more sophisticated domain validation mechanism.  For this example,
    #  we'll allow redirects to the same domain as the current application.
    #  This is still not perfect, but better than allowing arbitrary domains.

    # Get the current application's domain (if possible).  This is highly dependent
    # on the web framework you're using (e.g., Flask, Django).  The example below
    # assumes you can get it from an environment variable.  If not, you'll need
    # to adapt this part.
    current_domain = os.environ.get('APP_DOMAIN')  # Example: 'example.com'

    if current_domain:
        if url.netloc != current_domain and url.netloc != 'www.' + current_domain:
            return False  # Different domain, not allowed

    # Additional checks (optional but recommended):
    # - Check for relative URLs that could be manipulated.
    # - Check for javascript: or data: URLs.
    # - Check for IP addresses instead of domain names (can be misleading).

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

    # Regular expression to match alphanumeric characters, hyphens, and a period.
    #  This is the *least* secure part of the code.  It's very easy to bypass.
    #  The is_safe_url function is *much* more important.
    regex = r"^[a-zA-Z0-9\-]+\."

    if target and re.match(regex, target) and is_safe_url(target):
        # Redirect to the target URL (if it's safe).
        status = '302 Found'
        headers = [('Location', target)]
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

