from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
import string

app = Flask(__name__)

# Configure Flask-Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]
)

# Configure Flask-Talisman (Security Headers)
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\' https://example.com',
    'img-src': '\'self\' data:',
    'style-src': '\'self\' https://example.com'
})

# Configure Flask-WTF (CSRF Protection)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')  # Replace with a strong secret key using an environment variable.  This is CRUCIAL for security!
if not app.config['SECRET_KEY']:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set!")
csrf = CSRFProtect(app)

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# Input Sanitization Function
def sanitize_input(input_string):
    """
    Sanitizes the input string to prevent injection attacks.
    Raises TypeError if input is not a string.
    """
    if not isinstance(input_string, str):
        raise TypeError("Input must be a string.")

    # Whitelist allowed characters (alphanumeric, space, and a few common punctuation marks)
    allowed_chars = string.ascii_letters + string.digits + " .,!?"
    sanitized_string = ''.join(c for c in input_string if c in allowed_chars)
    sanitized_string = sanitized_string.replace('\n', '').replace('\r', '') # Remove newlines and carriage returns
    return sanitized_string


# Admin Check Function
def check_admin_status(username):
    """
    Securely checks if a user is an administrator.
    This is a placeholder and should be replaced with a proper authentication/authorization mechanism.
    """
    admin_username = os.environ.get("ADMIN_USERNAME")
    if admin_username:
        return username == admin_username
    else:
        logger.error("ADMIN_USERNAME environment variable not set. Admin check disabled.  Application may not function correctly.")
        # Consider raising an exception if an admin user is required:
        # raise RuntimeError("ADMIN_USERNAME environment variable not set.")
        return False


# Password Hashing Functions
def hash_password(password):
    """Hashes a password using Werkzeug's secure hashing function.
    Salting is automatically handled. Salting adds a unique, random value to each password before hashing it, preventing rainbow table attacks.
    """
    hashed_password = generate_password_hash(password)
    return hashed_password


def verify_password(password, hashed_password):
    """Verifies a password against a hash."""
    return check_password_hash(hashed_password, password)


# Flask-WTF Form
class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        return f"Hello, {name}!"
    return render_template('index.html', form=form)


@app.route('/logging', methods=['POST'])
@limiter.limit("5/minute")  # Limit to 5 requests per minute
def logging_endpoint():
    """
    Endpoint to receive log messages.
    """
    try:
        log_message = request.form['message']
        sanitized_message = sanitize_input(log_message)
        logger.info(f"Received log message: {sanitized_message}")
        return "Log message received", 200
    except KeyError:
        return "Missing 'message' parameter", 400
    except TypeError:
        return "Invalid input type for 'message'", 400


if __name__ == '__main__':
    #  To run this example:
    #  1.  Install the required packages: pip install flask flask-wtf werkzeug flask-talisman flask-limiter
    #  2.  Set the FLASK_SECRET_KEY environment variable:  export FLASK_SECRET_KEY="your_secret_key" (or set it in your system's environment variables)
    #  3.  (Optional) Set the ADMIN_USERNAME environment variable: export ADMIN_USERNAME="admin"
    #  4.  Run the script: python your_script_name.py
    app.run(debug=True)

