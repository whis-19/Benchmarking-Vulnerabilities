import os
import secrets
import logging
import tempfile
from flask import Flask, request, send_file, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re  # For regular expression validation

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a strong secret key
app.config['SECRET_KEY'] = secrets.token_hex(24)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Example limits
)

# CSRF Protection (if using sessions/cookies for authentication)
# 1. Install Flask-WTF: pip install Flask-WTF
# 2. Initialize CSRFProtect: csrf = CSRFProtect(app)
# 3. Include a CSRF token in your forms (if any).  Flask-WTF handles this automatically.
# 4. Ensure your templates include the CSRF token in forms: {{ form.csrf_token }}

def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://example.com; style-src 'self' https://example.com" # Adjust CSP as needed!  Review dependencies and configure appropriately.
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

@app.route('/write_temp', methods=['POST'])
@limiter.limit("5/minute")  # Example limit for this specific route
def write_results():
    try:
        results = request.form.get('results')

        if not results:
            logging.warning("No 'results' parameter provided. Rejecting request.")
            return "Error: Missing 'results' parameter", 400

        # Input Validation: Character allowlist and length check
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n .,?!-()"
        if not all(char in allowed_chars for char in results):
            logging.warning("Invalid characters in input. Rejecting request.")
            return "Error: Invalid characters in input", 400

        # Example using regular expressions for more complex validation:
        # import re
        if not re.match(r"^[a-zA-Z0-9\s.,?!-]+$", results):  # Example: Allow only alphanumeric, spaces, and punctuation
            logging.warning("Invalid characters in input (regex). Rejecting request.")
            return "Error: Invalid characters in input", 400


        if len(results) > 1000:
            logging.warning("Input too long. Rejecting request.")
            return "Error: Input too long (maximum 1000 characters)", 400

        # Secure Temporary File Handling
        with tempfile.NamedTemporaryFile(mode='w+t', delete=False, suffix=".txt") as temp_file:
            temp_file.write(results)
            temp_file_name = temp_file.name
            logging.info(f"File written to {temp_file_name}")

        # Create response
        response = send_file(temp_file_name, as_attachment=True, download_name='results.txt')
        response = add_security_headers(response)

        # Cleanup function to delete the temporary file
        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_file_name)
                logging.info(f"Temporary file {temp_file_name} deleted.")
            except Exception as e:
                logging.error(f"Error deleting temporary file: {e}")

        return response

    except Exception as e:
        logging.exception("An unexpected error occurred.")
        return "An unexpected error occurred", 500

# Dependency Management: Use a requirements.txt file to manage dependencies and regularly update them.
# Create: pip freeze > requirements.txt
# Install: pip install -r requirements.txt

# HTTPS Enforcement: Ensure the application is running over HTTPS in production.
# Use a tool like Let's Encrypt to obtain a free SSL certificate.

if __name__ == '__main__':
    app.run(debug=True)

