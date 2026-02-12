import os
import subprocess
import shlex
import logging
import re  # Import the regular expression module

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example: 200 requests per day, 50 per hour
)

# Define an allowlist of allowed packages.  This is crucial.
ALLOWED_PACKAGES = ["requests", "flask", "beautifulsoup4"]  # Example packages

# API Key for Authentication (replace with a more secure method in production)
API_KEY = "your_secret_api_key"  # NEVER hardcode in production. Use env vars.

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            logger.warning("Unauthorized access attempt")
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


def is_safe_package_name(package_name):
    """
    Checks if the package name is safe.  This is a critical security measure.
    """
    if not isinstance(package_name, str):
        logger.warning(f"Invalid package name type: {type(package_name)}")
        return False  # Reject non-string input

    # Check against the allowlist
    if package_name not in ALLOWED_PACKAGES:
        logger.warning(f"Package name not in allowlist: {package_name}")
        return False

    # Further checks (optional, but recommended):
    # Use a regular expression to validate the package name format.
    # This allows hyphens and underscores, but prevents other potentially malicious characters.
    package_name_regex = r"^[a-zA-Z0-9_-]{1,64}$"  # Limit length to 1-64 characters
    if not re.match(package_name_regex, package_name):
        logger.warning(f"Package name failed regex validation: {package_name}")
        return False

    return True


@app.route('/install')
@limiter.limit("5/minute")  # Example: 5 requests per minute
@require_api_key
def install_package():
    """
    Get the package name from the request using 'package'.
    Install it using pip.
    Return the package name
    """
    package_name = request.args.get('package')

    if not package_name:
        logger.warning("Package name is missing from request")
        return jsonify({"error": "Package name is required"}), 400

    if not is_safe_package_name(package_name):
        return jsonify({"error": "Invalid package name"}), 400

    try:
        # Use subprocess.run with shlex.split for safer command execution
        # and capture output for logging/error handling.
        command = ["pip", "install", package_name]
        process = subprocess.run(command, capture_output=True, text=True, check=True)

        # Log the output (important for debugging and security monitoring)
        # Redact potentially sensitive information before logging
        stdout = process.stdout
        stderr = process.stderr

        # Example redaction (replace with more sophisticated methods if needed)
        if "API_KEY" in stdout:
            stdout = stdout.replace(API_KEY, "[REDACTED]")
        if "API_KEY" in stderr:
            stderr = stderr.replace(API_KEY, "[REDACTED]")

        logger.info(f"Command output: {stdout}")
        logger.info(f"Command errors: {stderr}")

        return jsonify({"message": f"Package {package_name} installed successfully"}), 200

    except subprocess.CalledProcessError as e:
        # Handle errors from the subprocess
        logger.error(f"Error installing package: {e}")
        logger.error(f"Return code: {e.returncode}")

        # Redact potentially sensitive information before logging
        stdout = e.stdout
        stderr = e.stderr

        # Example redaction (replace with more sophisticated methods if needed)
        if "API_KEY" in stdout:
            stdout = stdout.replace(API_KEY, "[REDACTED]")
        if "API_KEY" in stderr:
            stderr = stderr.replace(API_KEY, "[REDACTED]")

        logger.error(f"Stdout: {stdout}")
        logger.error(f"Stderr: {stderr}")
        return jsonify({"error": f"Failed to install package: {stderr}"}), 500
    except Exception as e:
        # Handle other potential errors
        logger.exception(f"Unexpected error: {e}")  # Use logger.exception to include traceback
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    #  Consider a more restrictive CSP in production
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Only if using HTTPS
    return response


if __name__ == '__main__':
    app.run(debug=True)

