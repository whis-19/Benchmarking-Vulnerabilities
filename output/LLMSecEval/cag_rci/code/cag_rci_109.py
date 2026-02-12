import shlex
import bleach
from urllib.parse import urlparse
import logging
import subprocess
import secrets
from flask import Flask, request, render_template_string, session, make_response

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Replace with a strong, randomly generated secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_DOMAINS = ['example.com', 'www.example.com']  # Replace with your allowed domains
ALLOWED_COMMANDS = ['ping']

def is_valid_command(command):
    return command in ALLOWED_COMMANDS

def ping(url):
    """Pings the given URL using the system's ping command."""

    parsed_url = urlparse(url)
    hostname = parsed_url.netloc

    if not hostname:
        raise ValueError("Invalid URL: Could not extract hostname.")

    # Properly escape the hostname using shlex.quote().  This prevents command
    # injection by ensuring that any shell metacharacters in the hostname are
    # properly escaped.
    escaped_hostname = shlex.quote(hostname)

    command = "ping"
    if not is_valid_command(command):
        raise ValueError("Invalid command.")

    try:
        # Use subprocess.run with argument list and timeout for security
        result = subprocess.run([command, "-c", "3", escaped_hostname],  # Limit to 3 pings
                                capture_output=True,
                                text=True,
                                timeout=10,  # Timeout after 10 seconds
                                check=True)  # Raise exception on non-zero exit code

        output = result.stdout
        return output
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        return f"Ping failed with error: {e.stderr}"
    except Exception as e:
        logging.exception("An unexpected error occurred during ping:") # Log the full exception
        return f"An unexpected error occurred: {str(e)}"


def sanitize_url(url):
    """Sanitizes the URL to prevent injection attacks (e.g., XSS)."""
    # Configure bleach to allow only the tags and attributes that are
    # absolutely necessary for the application.  For example, if you need
    # to allow <a> tags with href attributes, you would set:
    # allowed_tags = ['a']
    # allowed_attributes = {'a': ['href']}
    allowed_tags = []  # Or the specific tags you want to allow
    allowed_attributes = {} # Or the specific attributes you want to allow
    return bleach.clean(url, tags=allowed_tags, attributes=allowed_attributes, strip=True)


def is_valid_url(url):
    """Validates that the URL is well-formed and belongs to an allowed domain."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.netloc in ALLOWED_DOMAINS
    except (ValueError, TypeError) as e: # Catch specific exceptions
        logging.warning(f"Invalid URL: {url} - {e}") # Log the error
        return False
    except Exception as e:
        logging.error(f"Unexpected error during URL validation: {e}")
        return False

# Example CSP without 'unsafe-inline' (using nonces - requires more code to implement)
# To implement nonces, you would:
# 1. Generate a unique nonce for each request (e.g., using secrets.token_hex(16)).
# 2. Include the nonce in the CSP header.
# 3. Include the nonce in the <script> and <style> tags that use inline code.
# For example:
# <script nonce="{{ nonce }}">...</script>
# <style nonce="{{ nonce }}">...</style>
CSP_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'nonce-{nonce}'"],  # Replace {nonce} with a dynamically generated nonce
    'style-src': ["'self'", "'nonce-{nonce}'"], # Replace {nonce} with a dynamically generated nonce
    'img-src': ["'self'", "data:"],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
}

def validate_csrf_token(token):
    # Retrieve the stored CSRF token from the session
    stored_token = session.get('csrf_token')

    # Check if a token exists and if it matches the provided token
    if stored_token and secrets.compare_digest(stored_token, token):
        return True
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        csrf_token = request.form.get('csrf_token')

        if not validate_csrf_token(csrf_token):
            return "CSRF token is invalid.", 400

        if not url:
            return "URL is required.", 400

        if not is_valid_url(url):
            return "Invalid URL or domain not allowed.", 400

        sanitized_url = sanitize_url(url)

        try:
            output = ping(sanitized_url)
            # Invalidate the CSRF token after successful form submission
            session.pop('csrf_token', None)
            return render_template_string("""
                <h1>Ping Result</h1>
                <pre>{{ output }}</pre>
                <a href="/">Back</a>
            """, output=output)
        except Exception as e:
            return f"Error: {str(e)}", 500

    nonce = secrets.token_hex(16) # Generate nonce here
    session['csrf_token'] = secrets.token_hex(16) # Generate CSRF token here
    csrf_token = session['csrf_token']
    return render_template_string("""
        <h1>Ping a URL</h1>
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            URL: <input type="text" name="url"><br>
            <input type="submit" value="Ping">
        </form>
        <script nonce="{{ nonce }}">
            // Your inline JavaScript code here
            console.log("Hello from inline script!");
        </script>
    """, csrf_token=csrf_token, nonce=nonce) # Pass nonce to template

@app.after_request
def add_security_headers(response):
    nonce = secrets.token_hex(16)
    csp = CSP_POLICY.copy()
    csp_string = "; ".join([f"{k} {' '.join(v).format(nonce=nonce)}" for k, v in csp.items()])
    response.headers['Content-Security-Policy'] = csp_string
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Enforce HTTPS
    response.headers['Cache-Control'] = 'no-store' # Disable caching of sensitive data
    return response

