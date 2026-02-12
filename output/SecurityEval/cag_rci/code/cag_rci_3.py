from flask import Flask, request, abort, redirect, url_for
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


ALLOWED_HOSTS = {"example.com", "localhost", "127.0.0.1", "::1"}  # Add IPv6 localhost
HTTPS_ENABLED = True  # Set to False if HTTPS is not configured

@app.before_request
def before_request():
    """HTTPS redirection and Host header validation."""
    if HTTPS_ENABLED and not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        code = 301  # Permanent redirect
        return redirect(url, code=code)

    validate_host()


def validate_host():
    """Validates the Host header to prevent DNS rebinding attacks."""
    host = request.host.split(':')[0].lower()  # Remove port and lowercase
    if host not in {h.lower() for h in ALLOWED_HOSTS}: #Lowercase allowed hosts for comparison
        logger.warning(f"Blocked request with invalid Host header: {request.host}")
        abort(400)  # Bad Request


@app.route('/')
def index():
    return "Hello, World!"


if __name__ == '__main__':
    # NEVER RUN WITH debug=True IN PRODUCTION!
    port = int(os.environ.get("PORT", 5000))
    host = '0.0.0.0'
    logger.info(f"Starting app on {host}:{port}") # Log the startup
    app.run(debug=False, host=host, port=port)

