import re
import shlex
import subprocess
import socket  # For alternative pinging
import os
from flask import Flask, request, abort, make_response, render_template_string, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example rate limits
    storage_uri="memory://"  # Use a persistent storage for production
)

CSP_POLICY = "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self';"  # Example - customize!
# Example CSP Directives:
#   - script-src 'self' https://example.com;  # Allow scripts from the same origin and https://example.com
#   - object-src 'none';  # Disable plugins like Flash
#   - base-uri 'self';  # Restrict the base URL for relative URLs

def sanitize_command_argument(argument):
    """
    Sanitizes a command argument to prevent command injection.  This is crucial.
    """
    # Whitelist approach: allow only alphanumeric characters and a few safe characters.
    sanitized_argument = re.sub(r'[^a-zA-Z0-9._-]', '', argument)
    return sanitized_argument

# Before Request - Set CSP Header
@app.before_request
def before_request():
    response = make_response()
    nonce = os.urandom(16).hex()  # Generate a unique nonce for each request
    g.nonce = nonce  # Store the nonce in the request context
    csp = CSP_POLICY.format(nonce=nonce)
    response.headers.set('Content-Security-Policy', csp)
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'SAMEORIGIN')
    response.headers.set('X-XSS-Protection', '1; mode=block')
    return response

@app.route('/ping', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit the ping endpoint
def ping_url():
    hostname = request.form.get('hostname')

    if not hostname:
        abort(400, description="Hostname is required.")

    # Input Validation: Check if the hostname looks like a valid hostname
    if not re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", hostname):
        abort(400, description="Invalid hostname format.")

    sanitized_hostname = sanitize_command_argument(hostname)
    quoted_hostname = shlex.quote(sanitized_hostname)  # Quote after sanitization

    try:
        # Option 1: Using subprocess.run (safer than subprocess.call)
        command = ["ping", "-c", "1", quoted_hostname]  # Limit to one ping
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True) # Added timeout and check=True
        pong = result.stdout

        # Option 2:  Alternative using socket (more control, less reliance on external command)
        # try:
        #     socket.gethostbyname(sanitized_hostname) # Resolve hostname
        #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     sock.settimeout(2)
        #     sock.connect((sanitized_hostname, 80)) # Try connecting to port 80
        #     pong = f"Connection to {sanitized_hostname} successful."
        #     sock.close()
        # except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
        #     pong = f"Error connecting to {sanitized_hostname}: {e}"

        # SSTI Mitigation:  Avoid passing user-controlled data directly to the template.
        # Instead, pass a pre-defined message and the sanitized hostname.
        message = f"Pinged {sanitized_hostname}."
        return render_template_string("<h1>{{ message }}</h1><pre>{{ pong }}</pre>", message=message, pong=pong, nonce=g.nonce)

    except subprocess.CalledProcessError as e:
        app.logger.exception(f"Ping command failed: {e}")
        abort(500, description=f"Ping command failed with exit code {e.returncode}.")
    except socket.gaierror as e:
        app.logger.exception(f"Hostname resolution failed: {e}")
        abort(500, description="Invalid hostname.")
    except TimeoutExpired as e:
        app.logger.exception(f"Ping command timed out: {e}")
        abort(500, description="Ping command timed out.")
    except Exception as e:
        app.logger.exception("Unexpected error during ping execution")
        abort(500, description="An unexpected error occurred.")

if __name__ == '__main__':
    # Example of structured logging (requires a logging library like structlog)
    # import structlog
    # log = structlog.get_logger()
    # log.info("Application started", event="app_start")

    # In a production environment, configure log rotation and secure storage.

    # Defense in Depth:  We're using multiple layers of security controls:
    #   - Input validation
    #   - Input sanitization
    #   - shlex.quote
    #   - subprocess.run with timeout and check=True
    #   - Rate limiting
    #   - CSP
    #   - Error handling
    #   - Logging

    app.run(debug=True)

