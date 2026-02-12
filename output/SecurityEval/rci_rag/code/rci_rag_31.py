from flask import Flask, request, logging, abort
import html
import re
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import secrets  # For generating strong secret keys

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

# Configure CORS (Restrict origins in production!)
CORS(app, origins=["https://yourdomain.com"])  # Replace with your actual domain(s)

# Configure Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Set the secret key from an environment variable
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    # Generate a strong secret key if one isn't set in the environment
    SECRET_KEY = secrets.token_hex(24)  # Generates a 48-character hex string (24 bytes)
    print("WARNING: No FLASK_SECRET_KEY set.  Using a generated key.  This is NOT secure for production!")
    # Consider saving this generated key to a file or database for persistence
    # and loading it on subsequent startups.  However, environment variables
    # are generally the preferred approach.
    # Example of saving to a file (USE WITH CAUTION - ensure file permissions are correct):
    # with open("secret_key.txt", "w") as f:
    #     f.write(SECRET_KEY)
    # SECRET_KEY = open("secret_key.txt").read().strip() # Load from file

app.config['SECRET_KEY'] = SECRET_KEY

# Define acceptable input length
MAX_NAME_LENGTH = 100

# Define a list of acceptable characters (alphanumeric, spaces, and some common punctuation)
# Consider Unicode character classes if you need to support multiple languages
ALLOWED_CHARACTERS = r"^[a-zA-Z0-9\s.,?!-]+$"

# Define a denylist of potentially harmful words (case-insensitive) - REMOVE THIS!
# DENYLIST = ["<script>", "</script>", "javascript:", "vbscript:", "onload=", "onerror=", "<iframe>", "</iframe>"]


@app.route('/logger')
@limiter.limit("10 per minute")  # Apply rate limiting to this endpoint
def logger():
    """
    Get the "name" value from the GET request and log it as an information message.
    Validates the user input to prevent security vulnerabilities.
    """
    name = request.args.get('name')

    if not name:
        logging.warning("Missing 'name' parameter in the request.")
        return "Error: Missing 'name' parameter", 400

    # Input Type Validation
    if not isinstance(name, str):
        logging.warning("Invalid input type for 'name'. Expected string.")
        return "Error: Invalid input type. Expected string.", 400

    # Input Length Validation
    if len(name) > MAX_NAME_LENGTH:
        logging.warning(f"Input 'name' exceeds maximum length of {MAX_NAME_LENGTH}.")
        return f"Error: Input too long. Maximum length is {MAX_NAME_LENGTH}.", 400

    # Input Sanitization (remove leading/trailing whitespace)
    name = name.strip()

    # Accept List Validation (Allowed Characters)
    if not re.match(ALLOWED_CHARACTERS, name):
        logging.warning(f"Input 'name' contains invalid characters. Allowed characters: {ALLOWED_CHARACTERS}")
        return f"Error: Invalid characters in input. Allowed characters: {ALLOWED_CHARACTERS}", 400

    # Denylist Validation (REMOVE THIS ENTIRE SECTION!)
    # name_lower = name.lower()
    # for item in DENYLIST:
    #     if item in name_lower:
    #         logging.warning(f"Input 'name' contains a forbidden word: {item}")
    #         return "Error: Input contains forbidden words.", 400

    # Encoding and Escaping (HTML escaping)
    escaped_name = html.escape(name)

    logging.info(f"Received name: {escaped_name}")  # Log the escaped name
    return f"Logged name: {escaped_name}", 200


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit errors."""
    logging.warning("Rate limit exceeded.")
    return "Error: Rate limit exceeded. Please try again later.", 429


if __name__ == '__main__':
    # NEVER USE debug=True IN PRODUCTION
    app.run(debug=False)  # Change to debug=False in production

