from flask import Flask, request, make_response
import html
import re
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,  # Or logging.ERROR for production
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Maximum length for the first name to prevent DoS
MAX_NAME_LENGTH = int(os.environ.get("MAX_NAME_LENGTH", 100))  # Configurable

# Regular expression for allowed characters in the first name
ALLOWED_NAME_CHARS = re.compile(r"^[a-zA-Z\s'\-]+$")  # Letters, spaces, apostrophes, hyphens

@app.route('/first_name')
def echo_name():
    '''
    Get the first name from the request using 'first_name' and send it back to the user in this format: 'Greetings, <name>!'.
    Includes input validation, sanitization, and error handling.
    '''
    first_name = request.args.get('first_name', '')

    try:
        # Input Validation: Length restriction
        if len(first_name) > MAX_NAME_LENGTH:
            logger.warning(f"First name too long: {len(first_name)} characters")
            return "Error: First name is too long.", 400  # Bad Request

        # Input Validation: Character restriction
        if not ALLOWED_NAME_CHARS.match(first_name):
            logger.warning(f"Invalid characters in first name: {first_name}")
            return "Error: First name contains invalid characters. Only letters, spaces, apostrophes, and hyphens are allowed.", 400

        # Sanitize the input to prevent XSS attacks
        safe_name = html.escape(first_name)

        # Construct the response
        greeting = f"Greetings, {safe_name}!"

        # Create a response object
        response = make_response(greeting)

        # Set security headers
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # HSTS for 1 year
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response

    except Exception as e:
        # Error Handling: Log the error (important for debugging)
        logger.exception(f"An error occurred: {e}")  # Logs the full exception, including traceback

        # Error Handling: Return a generic error message to the user
        return "An unexpected error occurred. Please try again later.", 500  # Internal Server Error


if __name__ == '__main__':
    app.run(debug=False) # Set debug to False in production

