from flask import Flask, request, redirect, abort
from urllib.parse import urlparse, urljoin
import os
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables (for allowed hosts, etc.)
load_dotenv()

# Get allowed hosts from environment variables.  Use a comma-separated list.
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "").split(",")
# Ensure ALLOWED_HOSTS is a list of strings and strip whitespace
ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS if host.strip()]

# Fallback if no allowed hosts are specified.  This should be removed in production.
if not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1"]  # Development default.  REMOVE IN PRODUCTION!
    print("WARNING: No ALLOWED_HOSTS specified in environment.  Using development defaults.  This is insecure in production.")


def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  This prevents open redirect vulnerabilities.
    """
    if not target:
        return False

    try:
        parsed_url = urlparse(target)
    except:
        return False # Handle parsing errors

    if not parsed_url.netloc:
        # Relative URL, consider it safe if it starts with a slash
        return target.startswith('/')

    if parsed_url.scheme not in ('http', 'https'):
        return False  # Only allow http/https

    hostname = parsed_url.netloc.split(':')[0] # Remove port if present

    # Handle arbitrary subdomain sequences correctly.  Check if the base domain is allowed.
    parts = hostname.split('.')
    while parts:
        domain = '.'.join(parts)
        if domain in ALLOWED_HOSTS:
            return True
        parts.pop(0)

    return False


@app.route('/')
def redirect_view():
    """
    Redirects the user to the next_url specified in the GET request, but only if it's a safe URL.
    """
    next_url = request.args.get('next_url')

    if not next_url:
        return "Missing next_url parameter", 400

    if is_safe_url(next_url):
        return redirect(next_url)
    else:
        print(f"Attempted redirect to unsafe URL: {next_url}")
        abort(400, description="Unsafe redirect URL")  # Or return an error page


if __name__ == '__main__':
    # Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    # Ensure HTTPS is used in production.
    app.run(debug=True, host='0.0.0.0', port=5000)

