from flask import Flask, request, session, make_response, redirect
import ast
import html
import logging
import os
import re  # Import the regular expression module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Configure logging (optional, but recommended)
logging.basicConfig(level=logging.INFO)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)

# HTTPS Redirect (Example - Adapt to your deployment environment)
@app.before_request
def before_request():
    if os.environ.get('FLASK_ENV') == 'production' and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)


@app.route('/parse_string_to_dict')
@limiter.limit("10 per minute")  # Apply rate limiting to this endpoint
def parse_string_to_dict():
    '''
    Get the formatted string from the request using 'formattedStr'.
    Safely convert it to a dictionary using ast.literal_eval.
    '''
    formatted_str = request.args.get('formattedStr')

    if not formatted_str:
        return "Error: 'formattedStr' parameter is missing.", 400

    try:
        # More robust sanitization (example - adapt to your needs)
        # This allows alphanumeric characters, spaces, common dictionary characters,
        # negative numbers, and decimal points.  Consider whitelisting instead.
        sanitized_str = re.sub(r"[^\w\s{}:,'\"-.]", "", formatted_str)

        # Use ast.literal_eval to safely evaluate the string as a dictionary
        data_dict = ast.literal_eval(sanitized_str)

        # Escape special characters before writing back to the page
        escaped_dict = {k: html.escape(str(v)) for k, v in data_dict.items()}

        return str(escaped_dict), 200

    except (ValueError, SyntaxError) as e:
        logging.error(f"Error parsing string: {e}")
        return "Error: Invalid format.", 400  # Generic error message for the user
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return "Error: An unexpected error occurred.", 500

# Example of setting HttpOnly flag for session cookie
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"  # Customize this!  Added CDNs for common resources
    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Strict') # Secure=True requires HTTPS, using Strict SameSite
    return response

# Example of validating data in the request
@app.route('/process_data', methods=['POST'])
@csrf.exempt # Remove this in production and implement proper CSRF handling with forms
@limiter.limit("10 per minute") # Apply rate limiting to this endpoint
def process_data():
    data = request.form

    # Validate the data
    if not data:
        return "Error: No data received.", 400

    # Example validation: Check if 'username' is present and not empty
    if 'username' not in data or not data['username']:
        return "Error: Username is required.", 400

    # Example validation: Check if 'email' is a valid email format (basic check)
    if 'email' in data and '@' not in data['email']:
        return "Error: Invalid email format.", 400

    # More robust email validation using regex
    if 'email' in data and not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
        return "Error: Invalid email format.", 400

    # Process the data (after validation)
    username = html.escape(data['username'])
    email = html.escape(data.get('email', ''))  # Use get() to handle optional fields

    return f"Data received: Username = {username}, Email = {email}", 200

if __name__ == '__main__':
    # Never run with debug=True in production!
    # Ensure the application is served over HTTPS for secure cookies to work correctly.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

# Further Security Considerations:
# 1. Customize the Content-Security-Policy (CSP) to allow only necessary resources. Use a CSP generator for assistance.
# 2. Implement CSRF protection using Flask-WTF. This involves adding a CSRF token to forms and validating it on the server-side.
# 3. Implement rate limiting to prevent abuse and denial-of-service attacks (e.g., using Flask-Limiter).
# 4. Use a requirements.txt file to manage dependencies and ensure consistent versions.
# 5. Regularly update Flask and all other dependencies to patch security vulnerabilities.
# 6. Redirect HTTP requests to HTTPS using middleware or server configuration.
# 7. Implement more comprehensive data validation using libraries like Marshmallow or Cerberus.
# 8. Monitor logs for suspicious activity and security events.

