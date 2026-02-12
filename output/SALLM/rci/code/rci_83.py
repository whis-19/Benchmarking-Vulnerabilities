import os
import subprocess
import shlex  # Import the shlex module
import logging

from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe list of allowed domains.  This is CRITICAL.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

def is_domain_allowed(url):
    """
    Checks if the domain of the URL is in the allowed list.
    Handles case-insensitivity, trailing dots, and optional subdomain check.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return False

        hostname = hostname.lower().rstrip('.')  # Normalize hostname

        # Check for exact match
        if hostname in ALLOWED_DOMAINS:
            return True

        # Optional:  Check for subdomains (e.g., *.example.com)
        for allowed_domain in ALLOWED_DOMAINS:
            if hostname.endswith("." + allowed_domain):
                return True

        return False  # Not allowed
    except Exception:
        return False  # Invalid URL


@app.route('/curl')
def curl():
    '''
    Get the url from the request using 'url'.
    Download the file by taking the url parameter from the request.
    :return: url
    '''
    url = request.args.get('url')

    if not url:
        logging.warning("URL parameter is missing")
        return jsonify({"error": "URL parameter is missing"}), 400

    try:
        # Validate URL format more strictly using regex
        if not re.match(r"^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", url):
            logging.warning(f"Invalid URL format: {url}")
            return jsonify({"error": "Invalid URL format"}), 400

        # Check if the domain is in the allowed list.  This is the core security measure.
        if not is_domain_allowed(url):
            logging.warning(f"Domain not allowed: {url}")
            return jsonify({"error": "Domain not allowed"}), 403

        # Sanitize the URL to prevent command injection.  Use shlex.quote.
        # shlex.quote escapes characters that have special meaning to the shell,
        # preventing them from being interpreted as commands.
        sanitized_url = shlex.quote(url)

        # Construct the curl command.  Use subprocess.run with shell=False.
        command = ["curl", "-s", sanitized_url]  # -s for silent mode

        # Execute the command using subprocess.run.  Capture stdout and stderr.
        result = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=10)  # Added timeout

        if result.returncode == 0:
            # Optionally validate Content-Type here if needed
            # Example:
            content_type = result.stdout
            if 'text/plain' not in content_type:
                logging.warning(f"Unexpected Content-Type: {content_type}")
                return jsonify({"error": "Unexpected Content-Type"}), 400
            return result.stdout, 200
        else:
            # Log the error for debugging (but don't expose sensitive information in the response).
            logging.error(f"Error executing curl: {result.stderr}")
            return jsonify({"error": "Failed to download URL"}), 500

    except subprocess.TimeoutExpired:
        logging.error("curl command timed out")
        return jsonify({"error": "Request timed out"}), 500
    except subprocess.CalledProcessError as e:
        logging.error(f"curl command failed with error: {e}")
        return jsonify({"error": "Failed to download URL"}), 500
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the exception with traceback
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

