from flask import Flask, request, make_response, session, render_template_string
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import html
import re
import os
import logging

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Set a strong, random secret key for session management and CSRF protection
# In a production environment, this should be stored securely (e.g., environment variable)
app.config['SECRET_KEY'] = os.urandom(24)

# Enable CSRF protection globally
csrf = CSRFProtect(app)

# Configuration for Content Security Policy (CSP)
# This is a starting point; customize it based on your application's needs.
CSP_POLICY = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Consider adding specific CDN URLs or nonces/hashes
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\''
}

# Function to generate CSP header string from the policy dictionary
def generate_csp_header(policy):
    return '; '.join(f"{directive} {value}" for directive, value in policy.items())


# Define a Flask-WTF form for handling the name input
class NameForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Define the route for displaying and processing the name
@app.route('/showName', methods=['GET', 'POST'])
def name():
    """
    Handles the display and processing of the name input.
    Includes CSRF protection, input validation, sanitization, and security headers.
    """
    form = NameForm()

    if form.validate_on_submit():
        name = form.name.data

        # Input Validation: Check the length of the name
        if len(name) > 100:
            logging.warning("Invalid input: Name exceeds maximum length.")
            return "Error: Invalid input", 400  # Bad Request

        # Input Validation: Check if the name contains only alphanumeric characters and spaces
        # Regular Expression Denial of Service (ReDoS) Mitigation: Keep regex simple and test performance.
        if not re.match(r"^[a-zA-Z0-9\s]+$", name):
            logging.warning("Invalid input: Name contains invalid characters.")
            return "Error: Invalid input", 400

        # Input Sanitization: Escape HTML characters to prevent Cross-Site Scripting (XSS)
        escaped_name = html.escape(name)

        # Construct the response
        response_text = f"Hello, {escaped_name}!"
        response = make_response(response_text)

        # Set Security Headers
        # Content Security Policy (CSP):  Customize this based on your application's needs.
        response.headers['Content-Security-Policy'] = generate_csp_header(CSP_POLICY)

        # X-Content-Type-Options: Prevent MIME sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # X-Frame-Options: Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'

        # HTTP Strict Transport Security (HSTS): Enforce HTTPS
        # Start with a shorter max-age and gradually increase it.
        # Ensure HSTS is configured at the web server level for better performance and reliability.
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

        # Cache-Control: Prevent caching of sensitive data
        # Evaluate data sensitivity carefully before deciding on a caching strategy.
        response.headers['Cache-Control'] = 'no-store'

        # Log successful operation
        logging.info(f"Processed name: {escaped_name}")

        return response

    # Render the form template
    return render_template_string('''
        <form method="post">
            {{ form.csrf_token }}
            {{ form.name.label }} {{ form.name() }}
            {{ form.submit() }}
        </form>
    ''', form=form)


# Main entry point for the application
if __name__ == '__main__':
    # Run the Flask app in debug mode (for development)
    # Disable debug mode in production
    app.run(debug=False, host='0.0.0.0', port=5000)

