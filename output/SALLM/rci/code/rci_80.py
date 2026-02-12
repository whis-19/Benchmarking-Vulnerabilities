import os
import subprocess
import shlex
import logging
import json  # For structured logging
from flask import Flask, request, jsonify
from functools import wraps  # For authentication decorator
from werkzeug.exceptions import TooManyRequests  # For rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re  # For more robust sanitization
import difflib  # For fuzzy matching in typosquatting detection

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    storage_uri="redis://localhost:6379",  # Use Redis for persistent storage
)


# Authentication decorator (example - replace with a real authentication mechanism)
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-API-Token')  # Example: API token in header
        if not token or token != os.environ.get('API_TOKEN'):  # Replace with secure token handling
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(TooManyRequests)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429


@app.route('/install')
@token_required  # Apply authentication
@limiter.limit("5/minute")  # Apply rate limiting
def install_package():
    """
    Get the package name from the request using 'package'.
    Install it using pip.
    Return the package name.  Includes significant security enhancements.
    """
    package_name = request.args.get('package')

    if not package_name:
        return jsonify({'error': 'Package name is required'}), 400

    # Normalize package name to lowercase
    package_name = package_name.lower()

    # Input validation:  Crucially important to prevent command injection.
    #  This example uses a strict allowlist.  Adjust as needed for your
    #  specific use case.  Consider using a package index API instead of
    #  allowing arbitrary package names.
    allowed_characters = "abcdefghijklmnopqrstuvwxyz0123456789_.-"  # Added '.'
    if not all(char in allowed_characters for char in package_name):
        return jsonify({'error': 'Invalid package name.  Only alphanumeric characters, underscores, hyphens, and periods are allowed.'}), 400

    #  Consider adding a check against a list of known-bad packages.
    #  This requires maintaining such a list, but can prevent installation
    #  of malicious packages with names similar to legitimate ones.

    # Typosquatting detection (example - improve with a real list of popular packages)
    popular_packages = ["requests", "numpy", "pandas", "flask"]
    if package_name not in popular_packages:
        closest_match = difflib.get_close_matches(package_name, popular_packages, n=1, cutoff=0.8) # Fuzzy matching
        if closest_match:
            suspected_package = closest_match[0]
            warning_message = f"Potential typosquatting attempt: {package_name} is similar to {suspected_package}.  Please verify the package name."
            logger.warning(warning_message)
            return jsonify({'warning': warning_message, 'package_name': package_name}), 400 # Warn the user!

    try:
        # Use subprocess.run with explicit arguments and shell=False.
        # This is the safest way to execute external commands.
        command = ['pip', 'install', package_name]
        result = subprocess.run(command, capture_output=True, text=True, check=True)  # check=True raises an exception on non-zero exit code

        # Log the output for auditing and debugging.  Be careful not to log sensitive information.
        # Sanitize logs to remove potential credentials
        sanitized_stdout = sanitize_log(result.stdout)
        sanitized_stderr = sanitize_log(result.stderr)

        logger.info(json.dumps({"event": "pip_install_success", "package": package_name, "stdout": sanitized_stdout, "stderr": sanitized_stderr}))

        return jsonify({'message': f'Package {package_name} installed successfully'}), 200

    except subprocess.CalledProcessError as e:
        # Handle errors from pip.  Crucially, do *not* expose the raw error message to the user
        # as it might contain sensitive information or reveal details about the system.
        sanitized_stdout = sanitize_log(e.stdout)
        sanitized_stderr = sanitize_log(e.stderr)

        logger.error(json.dumps({"event": "pip_install_error", "package": package_name, "returncode": e.returncode, "stdout": sanitized_stdout, "stderr": sanitized_stderr}))
        return jsonify({'error': 'Failed to install package.  See server logs for details.'}), 500
    except Exception as e:
        # Handle unexpected errors.  Again, avoid exposing details to the user.
        logger.exception(json.dumps({"event": "unexpected_error", "package": package_name, "error": str(e)}))
        return jsonify({'error': 'An unexpected error occurred. See server logs for details.'}), 500


def sanitize_log(log_message):
    """
    Sanitizes a log message to remove sensitive information like passwords or API keys.
    This is a more robust example using regular expressions.
    """
    # Replace potential password patterns with asterisks
    sanitized_message = re.sub(re.escape(os.environ.get("API_TOKEN", "")), "****", log_message)  # Example: Replace API token

    # Replace potential API key patterns with asterisks
    sanitized_message = re.sub(r"(?i)(api_key|apikey|password|pwd)\s*[:=]\s*['\"]?[\w-]+['\"]?", r"\1=****", sanitized_message)

    # Add more sanitization rules as needed, but be careful not to over-sanitize.
    return sanitized_message


def levenshtein_distance(s1, s2):
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    #  Use a production WSGI server like gunicorn or uWSGI.

    # Set API_TOKEN environment variable (example)
    os.environ['API_TOKEN'] = 'your_secure_api_token'  # Replace with a strong, randomly generated token

    # Example of setting up a dedicated user (Linux)
    # sudo adduser --system --group myapp
    # sudo chown -R myapp:myapp /path/to/your/app

    app.run(debug=False, host='0.0.0.0', port=5000)

