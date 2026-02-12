import subprocess
import sys
import os
from flask import Flask, request, render_template, session, abort
from urllib.parse import urlparse
import re
import tldextract
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL, Regexp, Length
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

ALLOWED_COMMANDS = ["ping"]  # Whitelist of allowed commands

class PingForm(FlaskForm):
    """
    Flask-WTF form for the ping functionality, including CSRF protection.
    """
    url = StringField('URL', validators=[
        DataRequired(),
        URL(require_tld=True),  # Basic URL validation
        Regexp(r'^[a-zA-Z0-9\-\.]*$', message="Invalid characters in URL"), # Strict character validation
        Length(max=200) # Length validation
    ])
    submit = SubmitField('Ping')


def is_valid_url(url):
    """
    Validates the URL to prevent command injection and other attacks.
    This function checks the URL scheme, netloc, TLD, and characters.
    This function is now largely redundant due to the Flask-WTF form validation.
    It's kept for defense-in-depth, but the form validation is the primary mechanism.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        # TLD Validation using tldextract
        ext = tldextract.extract(result.netloc)
        if not ext.suffix:  # No valid TLD found
            return False

        # Character Validation (more restrictive example)
        allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789.-") # Only lowercase letters, numbers, period, and hyphen
        if not all(c in allowed_chars for c in result.netloc.lower()): # Convert to lowercase for case-insensitive check
            return False

        # Length Limits (example)
        max_url_length = 200
        max_netloc_length = 100
        if len(url) > max_url_length or len(result.netloc) > max_netloc_length:
            return False

        return True
    except:
        return False

def execute_command(command, url):
    """
    Executes the specified command with the given URL.
    This function uses subprocess.run with proper quoting and escaping to prevent command injection.
    """
    try:
        # Validate the URL *again* before executing the command
        # This is a defense-in-depth measure, even though the form validates it.
        if not is_valid_url(url):
            logger.error(f"Invalid URL provided: {url}")
            return "Error: Invalid URL format."

        # Construct the command with the quoted URL
        full_command = [command, "-c", "3", url]  # Limit to 3 pings

        # Execute the command in a sandboxed environment (example: chroot)
        # Note: Setting up a proper chroot environment is complex and beyond the scope of this example.
        # This is just a placeholder.  A real implementation would involve creating a chroot jail.

        # Execute the command using subprocess.run with shell=False for safety
        process = subprocess.run(full_command, capture_output=True, text=True, timeout=10, check=True)

        # Sanitize output to prevent information disclosure
        output = process.stdout
        sanitized_output = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[IP Address Redacted]', output) #Redact IP addresses

        # Further sanitization: remove any lines containing "TTL="
        sanitized_output = "\n".join(line for line in sanitized_output.splitlines() if "TTL=" not in line)

        return sanitized_output
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out for URL: {url}")
        return "Error: Command timed out."
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode} for URL: {url}. Stderr: {e.stderr}")
        return "Error: Command failed." # Generic error message for the user
    except Exception as e:
        logger.exception(f"An unexpected error occurred for URL: {url}")
        return "An unexpected error occurred." # Generic error message for the user

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5/minute") # Apply rate limiting to the ping route
def ping():
    """
    Handles the ping functionality.
    This function retrieves the URL from the form, validates it using Flask-WTF,
    and executes the ping command.
    """
    form = PingForm()
    output = ""

    if form.validate_on_submit():
        url = form.url.data
        command = "ping"  # Use the allowed command directly
        if command in ALLOWED_COMMANDS:
            logger.info(f"Executing ping command for URL: {url}")
            output = execute_command(command, url)
        else:
            output = "Error: Command not allowed."

    return render_template('ping.html', form=form, output=output)

@app.route('/set_session', methods=['POST'])
def set_session():
    """
    Example of storing data in the session.  This is not directly used in the ping functionality
    but demonstrates how to store data server-side instead of sending it to the client.
    """
    session['example_data'] = request.form.get('data')
    return "Session data set!"

@app.route('/get_session')
def get_session():
    """
    Example of retrieving data from the session.
    """
    data = session.get('example_data', 'No data in session')
    return f"Session data: {data}"

@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many requests. Please try again later.", 429

@app.errorhandler(400)
def bad_request_error(e):
    return "Bad Request", 400

@app.errorhandler(500)
def internal_server_error(e):
    return "Internal Server Error", 500

@app.errorhandler(404)
def page_not_found(e):
    return "Page Not Found", 404

if __name__ == '__main__':
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # CSRF protection (more modern approach)
    app.run(debug=False, host='0.0.0.0', port=5000) # Disable debugging in production

