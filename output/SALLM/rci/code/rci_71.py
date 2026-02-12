import os
import subprocess
import shlex  # Import the shlex module
from flask import Flask, request, jsonify
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import ipaddress  # Import ipaddress
import html  # Import html for escaping
import socket

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Talisman for security headers
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '*'
})


# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit exceeded errors."""
    logging.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    return jsonify(error="Rate limit exceeded. Please try again later."), 429


@app.route('/ping')
@limiter.limit("5/minute")  # Apply rate limit to the ping endpoint
def ping():
    '''
    Get the link from the request using 'link' and ping the link.
    :return: link
    '''
    link = request.args.get('link')

    if not link:
        logging.warning("Missing 'link' parameter in request.")
        return jsonify(error="'link' parameter is missing."), 400

    try:
        # Attempt to parse as IP address
        ip_address = ipaddress.ip_address(link)
        target = str(ip_address)  # Use the string representation
    except ValueError:
        # If not a valid IP, attempt to resolve hostname
        try:
            target = socket.gethostbyname(link) # Resolve hostname to IP
            ipaddress.ip_address(target) # Validate resolved IP
        except (socket.gaierror, ValueError):
            logging.warning(f"Invalid URL or hostname: {link}")
            return jsonify(error="Invalid URL or hostname."), 400

    ping_count = os.environ.get('PING_COUNT', '3')
    ping_timeout = os.environ.get('PING_TIMEOUT', '10')

    try:
        result = subprocess.run(['ping', '-c', ping_count, target],
                                capture_output=True,
                                text=True,
                                timeout=int(ping_timeout))

        if result.returncode == 0:
            logging.info(f"Ping successful for: {link} (resolved to {target})")
            # Sanitize output for HTML context
            sanitized_stdout = html.escape(result.stdout)
            # Consider returning only success status instead of the output
            # return jsonify(message="Ping successful.")
            return jsonify(message=f"Ping successful:<br>{sanitized_stdout}")
        else:
            logging.error(f"Ping failed for: {link} (resolved to {target}). Error: {result.stderr}")
            # Don't expose full stderr in production
            return jsonify(error="Ping failed."), 500  # Generic error

    except subprocess.TimeoutExpired:
        logging.error(f"Ping timed out for: {link} (resolved to {target})")
        return jsonify(error="Ping timed out."), 500
    except Exception as e:
        logging.exception(f"An unexpected error occurred while pinging {link} (resolved to {target}): {str(e)}")
        return jsonify(error="An unexpected error occurred."), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

