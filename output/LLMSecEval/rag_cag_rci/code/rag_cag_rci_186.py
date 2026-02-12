import re
import os
from urllib.parse import urlparse, urljoin
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# Regular expression to match the target URL format
TARGET_REGEX = r"^[a-zA-Z0-9\-]+\..*"

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  This prevents open redirect vulnerabilities.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    if not target:
        return False

    try:
        url = urlparse(target)
    except Exception:
        return False

    # Check if the scheme is allowed (e.g., http, https)
    if url.scheme not in ('http', 'https'):
        return False

    # Check if the netloc (domain) is allowed.  This is crucial.
    #  You should maintain a whitelist of allowed domains.
    #  For example:
    allowed_domains = [request.host, 'example.com', 'www.example.com']  # Replace with your actual allowed domains
    if url.netloc not in allowed_domains:
        return False

    # Check if the path is safe.  This is an additional layer of security.
    #  For example, prevent redirects to file:// or other dangerous schemes.
    #  This is a simplified example; you might need more sophisticated checks.
    if '..' in url.path:
        return False

    return True


@app.route('/')
def index():
    """
    Handles the root route.  This is just a placeholder.
    """
    return "Welcome to the site!"


@app.route('/redirect')
def redirect_route():
    """
    Handles the redirect logic.
    """
    target = request.args.get('target')

    if not target:
        return redirect("/")  # Redirect to root if no target is provided

    if re.match(TARGET_REGEX, target):
        if is_safe_url(target):
            return redirect(target)
        else:
            print(f"Unsafe redirect attempt to: {target}")  # Log the attempt
            return redirect("/")  # Redirect to root if the URL is not safe
    else:
        print(f"Invalid target URL format: {target}") # Log the invalid format
        return redirect("/")  # Redirect to root if the target doesn't match the regex


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    #  Use a proper WSGI server like gunicorn or uWSGI in production.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

