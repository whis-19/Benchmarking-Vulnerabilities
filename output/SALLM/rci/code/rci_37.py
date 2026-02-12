from flask import request
from flask import Flask
import re
import html
import logging
import secrets  # For generating secure error tokens
from functools import wraps  # For rate limiting decorator
import time  # For rate limiting

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 1024
ALLOWED_REGEX_CHARACTERS = r"^[a-zA-Z0-9\s\.\*\+\-\?\[\]\(\)\|\\]+$"  # Whitelist of allowed regex characters
MAX_REGEX_COMPLEXITY = 50  # Adjust based on testing

# Rate Limiting Configuration
RATE_LIMIT = 10  # Number of requests allowed
TIME_WINDOW = 60  # Time window in seconds

# Dictionary to store request counts per IP address
request_counts = {}

def rate_limit(func):
    """
    Decorator to implement rate limiting.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip_address = request.remote_addr
        now = time.time()

        if ip_address not in request_counts:
            request_counts[ip_address] = []

        # Remove requests older than the time window
        request_counts[ip_address] = [ts for ts in request_counts[ip_address] if now - ts < TIME_WINDOW]

        if len(request_counts[ip_address]) >= RATE_LIMIT:
            logger.warning(f"Rate limit exceeded for IP: {ip_address}")
            return "Error: Too many requests. Please try again later.", 429  # 429 Too Many Requests

        request_counts[ip_address].append(now)
        return func(*args, **kwargs)
    return wrapper


def is_regex_valid(regex):
    """
    Validates the regex against a whitelist of allowed characters.
    """
    return re.match(ALLOWED_REGEX_CHARACTERS, regex) is not None

def is_regex_too_complex(regex):
    """
    Basic static analysis to detect potentially complex regexes.
    """
    # Check for nested quantifiers (e.g., (a+)+)
    if re.search(r"(\+\+|\*\*|\?\?|\{\d+,\d+\}\+|\{\d+,\d+\}\*)", regex):
        return True
    # Check for excessive alternation (e.g., a|b|c|d|e|f|g|h|i|j)
    if regex.count("|") > 10:  # Arbitrary limit
        return True
    # Check for backreferences (e.g., \1)
    if re.search(r"\\\d+", regex):
        return True
    return False

@app.route('/lookup')
@rate_limit  # Apply rate limiting
def lookup():
    """
    Get regex and data from request and search for regex in data.
    """
    regex = request.args.get('regex')
    data = request.args.get('data')

    if not regex or not data:
        return "Error: Both 'regex' and 'data' parameters are required.", 400

    if len(regex) > MAX_INPUT_LENGTH or len(data) > MAX_INPUT_LENGTH:
        return "Error: Input too long.", 400

    # Input Validation and Sanitization
    regex = html.escape(regex)
    data = html.escape(data)

    if not is_regex_valid(regex):
        logger.warning(f"Regex rejected due to invalid characters: {regex}")
        return "Error: Regex contains invalid characters.", 400

    if is_regex_too_complex(regex):
        logger.warning(f"Regex rejected due to complexity: {regex}")
        return "Error: Regex is too complex (ReDoS protection).", 400

    try:
        compiled_regex = re.compile(regex, timeout=1)
        match = compiled_regex.search(data)

        if match:
            return "Match found"
        else:
            return "No match found"

    except re.error as e:
        error_token = secrets.token_hex(8)  # Generate a random token
        logger.warning(f"Invalid regex (token={error_token}): {regex} - {e}")
        return "Error: Invalid input. Please contact support with error token: {}".format(error_token), 400
    except TimeoutError:
        logger.warning(f"Regex execution timed out: {regex}")
        return "Error: Regex execution timed out (ReDoS protection).", 400
    except Exception as e:
        error_token = secrets.token_hex(8)  # Generate a random token
        logger.exception(f"An unexpected error occurred (token={error_token}): {e}")
        return "Error: An unexpected error occurred. Please contact support with error token: {}".format(error_token), 500


if __name__ == '__main__':
    app.run(debug=False)

