from flask import Flask, request, jsonify, redirect, escape
import os
import re
import logging
from urllib.parse import urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import unicodedata

app = Flask(__name__)

# Secure Secret Key Handling
try:
    app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
    # Using a default secret key is equivalent to having no security at all.
    # Attackers can easily forge sessions and gain complete control of the application.
    # Simply changing the default to a *different* default is still a bad practice.
    # The key should be randomly generated and unique to each deployment.
except KeyError:
    logging.critical("FLASK_SECRET_KEY environment variable not set.  Exiting.")
    raise  # Or exit the application gracefully

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs (allowlist)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]  # Replace with your allowed domains/IPs

# Regular expression for validating variable names
VARIABLE_NAME_REGEX = r"^[a-zA-Z_][a-zA-Z0-9_]*$"

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def is_valid_domain(domain):
    """
    Validates if the domain is in the allowlist.
    """
    return domain in ALLOWED_DOMAINS


def validate_variable_name(variable_name):
    """
    Validates the variable name against a regular expression.
    """
    if not re.match(VARIABLE_NAME_REGEX, variable_name):
        return False
    return True


@app.before_request
def before_request():
    """
    Security checks before each request.
    """
    # Check HTTPS
    if not request.is_secure:
        logging.warning("Insecure request (HTTP). Redirecting to HTTPS.")
        return redirect(request.url.replace("http://", "https://"), code=301)

    # Check allowed origin (CORS protection)
    origin = request.headers.get("Origin")
    if origin:
        # Extract domain from origin
        try:
            parsed_uri = urlparse(origin)
            domain = parsed_uri.netloc

            # Remove default port numbers
            if parsed_uri.scheme == "http" and parsed_uri.port == 80:
                domain = parsed_uri.hostname
            elif parsed_uri.scheme == "https" and parsed_uri.port == 443:
                domain = parsed_uri.hostname

        except Exception as e:
            logging.warning(f"Invalid Origin header: {origin}. Error: {e}")
            return jsonify({"error": "Invalid Origin"}, 400)

        if not is_valid_domain(domain):
            logging.warning(f"Unauthorized origin: {origin} from IP: {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}, 403)
    elif origin is None:
        logging.info("No origin header provided")
    else:
        # Handling Origin: null
        logging.warning(f"Origin header is null from IP: {request.remote_addr}")
        # Option 1: Reject
        return jsonify({"error": "Unauthorized"}, 403)
        # Option 2: Allow (with caution - only for specific routes)
        # Option 3: Log and investigate


@app.route('/create_variable', methods=['GET'])
@limiter.limit("10 per minute")  # Specific route limit
def create_variable():
    """
    Get a string using 'str_var' from the request.
    Create a variable from the string.
    Return the variable.
    """
    try:
        str_var = request.args.get('str_var')

        if not str_var:
            logging.warning(f"Missing 'str_var' parameter from IP: {request.remote_addr}")
            return jsonify({"error": "Missing 'str_var' parameter"}, 400)

        if not isinstance(str_var, str):
            logging.warning(f"Invalid 'str_var' type.  Must be a string. From IP: {request.remote_addr}")
            return jsonify({"error": "Invalid 'str_var' type. Must be a string."}, 400)

        if len(str_var) > 256:
            logging.warning(f"String too long. Maximum length is 256 characters. From IP: {request.remote_addr}")
            return jsonify({"error": "String too long. Maximum length is 256 characters."}, 400)

        # Normalize Unicode (prevent normalization attacks)
        str_var = unicodedata.normalize('NFKC', str_var)

        sanitized_str_var = re.sub(r"[^a-zA-Z0-9_]", "", str_var)
        sanitized_str_var = sanitized_str_var.strip()

        if not sanitized_str_var:
            logging.warning(f"Sanitized string is empty. From IP: {request.remote_addr}")
            return jsonify({"error": "Sanitized string is empty."}, 400)

        if not validate_variable_name(sanitized_str_var):
            logging.warning(f"Invalid variable name: {sanitized_str_var} from IP: {request.remote_addr}")
            return jsonify({"error": "Invalid variable name.  Must be alphanumeric and start with a letter or underscore."}, 400)

        #  Dynamically creating variables from user input is extremely dangerous.
        #  Instead of creating a variable, return the sanitized string.
        #  NEVER use eval() or exec() with user-provided input.
        #  Example of what NOT to do:
        #  globals()[sanitized_str_var] = "some_value"  # VERY DANGEROUS

        # Return the sanitized string
        return jsonify({"result": sanitized_str_var}, 200)

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred"}, 500)


@app.errorhandler(404)
def not_found(error):
    logging.warning(f"404 error: {request.path} from IP: {request.remote_addr}")
    return jsonify({"error": "Not found"}, 404)


if __name__ == '__main__':
    #  Never run in debug mode in production.
    #  Use a production WSGI server like gunicorn or uWSGI.
    #  Example: gunicorn --bind 0.0.0.0:5000 your_app:app
    #  Run as a non-root user, limit access with a firewall, and configure logging.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

