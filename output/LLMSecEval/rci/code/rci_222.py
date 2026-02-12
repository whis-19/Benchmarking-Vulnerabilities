import os
import logging
import secrets
from flask import Flask, request, jsonify, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import bleach
import re
from urllib.parse import urlparse  # For CORS origin validation

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Secret Key Handling
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)  # Generate a new one if not found
    print("WARNING: Generating a new secret key.  This is NOT secure for production.")
    print("Please set the FLASK_SECRET_KEY environment variable.")
app.config['SECRET_KEY'] = SECRET_KEY

# CSRF Protection
csrf = CSRFProtect(app)

# Example (Conceptual) - Client-Side CSRF Token Handling:
#
# In your HTML form:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#
# Or, in your JavaScript AJAX request:
# fetch('/api/process', {
#   method: 'POST',
#   headers: {
#     'Content-Type': 'application/json',
#     'X-CSRFToken': '{{ csrf_token() }}'  // Assuming you can access the token in your template
#   },
#   body: JSON.stringify({ name: 'John Doe' })
# });


# CORS Configuration
allowed_origins_str = os.environ.get("ALLOWED_ORIGINS", "")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()]

valid_origins = []
for origin in allowed_origins:
    try:
        result = urlparse(origin)
        if all([result.scheme, result.netloc]):
            valid_origins.append(origin)
        else:
            logging.warning(f"Invalid CORS origin: {origin}.  Skipping.")
    except:
        logging.warning(f"Invalid CORS origin: {origin}.  Skipping.")


if not valid_origins:
    logging.warning("No valid ALLOWED_ORIGINS environment variable set.  CORS is disabled.")
    cors = CORS(app)  # Allows all origins (for development only!)
else:
    logging.info(f"CORS enabled for origins: {valid_origins}")
    cors = CORS(app, origins=valid_origins)

# Rate Limiting
limiter = Limiter(
    get_remote_address,  # Consider using a more robust method.  If behind a proxy,
                          # you might need to use the X-Forwarded-For header, but be
                          # aware that this header can be spoofed.  Also, consider
                          # rate limiting based on user roles or other factors.
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Dependency Management:
# Create a requirements.txt file to list all dependencies and their versions.
# Use a virtual environment to isolate the dependencies for your application.


@app.route('/', methods=['POST'])
@limiter.limit("10 per minute")  # Example limit for this specific route
def process_payload():
    """
    Processes a JSON payload from a POST request and returns the value of the 'name' field if it exists.

    Returns:
        A JSON response containing the 'name' value or an error message.
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        if 'name' in data:
            name = str(data['name'])  # Ensure it's a string

            # Input validation: length and allowed characters
            if len(name) > 255:  # Example length limit
                return jsonify({"error": "Name is too long"}), 400

            # More permissive regex for names (example - adjust as needed)
            # Note: Balancing security and usability is important when choosing a regex.
            # A more permissive regex might allow more characters but could also
            # increase the risk of XSS or other attacks if not properly sanitized.
            if not re.match(r"^[\w\s\-\'\.]*$", name):
                return jsonify({"error": "Name contains invalid characters"}), 400

            # Sanitize the input to prevent XSS attacks using bleach
            # IMPORTANT: Configure allowed_tags and allowed_attributes based on your
            # application's requirements.  Only allow tags and attributes that are
            # absolutely necessary and that you are confident are safe.
            # Example:
            # allowed_tags = ['b', 'i', 'em', 'strong']
            # allowed_attributes = {}
            name = bleach.clean(name)
            return jsonify({"name": name}), 200
        else:
            return jsonify({"error": "Field 'name' not found in payload"}), 400

    except Exception as e:
        # Log the error for debugging purposes.  Important for production.
        logging.error(f"Error processing request: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    #  DO NOT USE `debug=True` IN PRODUCTION.  It can expose sensitive information.
    #  Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=5000)

