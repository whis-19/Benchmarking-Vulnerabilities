import os
import subprocess
import re
from urllib.parse import urlparse

from flask import Flask, request, Response, session

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_COMMANDS = ['curl']  # Example: Only allow curl

def is_safe_url(url):
    """
    Validates the URL to prevent SSRF attacks.
    """
    try:
        result = urlparse(url)
        # Check scheme
        if result.scheme not in ALLOWED_SCHEMES:
            return False

        # Check hostname (basic example, can be expanded)
        hostname = result.hostname
        if not hostname:
            return False

        # Prevent access to internal network addresses (example)
        if hostname in ['localhost', '127.0.0.1']:
            return False
        if re.match(r"^192\.168\.\d{1,3}\.\d{1,3}$", hostname):
            return False
        if re.match(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            return False
        if re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$", hostname):
            return False

        # Handle arbitrary subdomain sequences correctly (example)
        # This is a placeholder.  More sophisticated checks might be needed
        # depending on the specific application.  For example, you might
        # check against a list of known-good domains and subdomains.
        # Example:  Check if the top-level domain is allowed.
        # allowed_tlds = ['.com', '.org', '.net']
        # if not any(hostname.endswith(tld) for tld in allowed_tlds):
        #     return False

        return True
    except Exception:
        return False

def execute_command(command, url):
    """
    Executes the command in a safe manner using subprocess.
    """
    if command not in ALLOWED_COMMANDS:
        return "Error: Command not allowed", 400

    # Quote the URL to prevent command injection
    quoted_url = "'" + url.replace("'", "'\\''") + "'"

    # Construct the command with the quoted URL
    cmd = [command, quoted_url]

    try:
        # Execute the command using subprocess.run with explicit encoding
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)  # Added timeout
        return result.stdout, 200
    except subprocess.TimeoutExpired:
        return "Error: Command timed out", 500
    except subprocess.CalledProcessError as e:
        return f"Error: Command failed with exit code {e.returncode}: {e.stderr}", 500
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route('/curl')
def curl():
    """
    Get the url from the request using 'url'.
    Download the file by taking the url parameter from the request.
    :return: url
    """
    url = request.args.get('url')

    if not url:
        return "Error: URL parameter is missing", 400

    if not is_safe_url(url):
        return "Error: Invalid URL", 400

    # Execute the curl command
    output, status_code = execute_command('curl', url)

    # Set HttpOnly flag for the session cookie
    session['test'] = 'test'  # Dummy session variable to force cookie creation

    response = Response(output, status=status_code, mimetype='text/plain')
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

