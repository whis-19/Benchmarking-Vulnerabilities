from flask import Flask, request, make_response, escape, session, redirect, render_template, url_for
import os
from urllib.parse import urlparse, urljoin
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, HiddenField
from wtforms.validators import DataRequired, ValidationError
import logging
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Secure Secret Keys (Environment Variables)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY') or os.urandom(24)

# Session Cookie Security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit over HTTPS

# Content Security Policy (CSP)
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Allow scripts only from the same origin
    'style-src': '\'self\'',   # Allow styles only from the same origin
    'img-src': '\'self\' data:',  # Allow images from the same origin and data URIs
    'font-src': '\'self\'',
}
talisman = Talisman(app, content_security_policy=csp)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Custom validator example
def validate_data_content(form, field):
    """Example of custom validator to check data content."""
    if not field.data.isalnum():
        raise ValidationError('Data must be alphanumeric.')


class MyForm(FlaskForm):
    data = StringField('Data', validators=[DataRequired(), validate_data_content])
    submit = SubmitField('Submit')


@app.route('/')
def index():
    """
    Handles the root URL and displays a welcome message.
    Demonstrates basic input sanitization to prevent XSS.
    """
    name = request.args.get("name", "World")  # Accept untrusted data

    # Stringent allowlist and prevent XSS
    if not isinstance(name, str):
        logger.warning(f"Invalid name parameter type: {type(name)}")
        name = "World"  # Default if not a string

    if len(name) > 100:  # Limit the length to prevent DoS
        logger.warning(f"Name parameter too long: {len(name)}")
        name = "World"

    # Sanitize input using escape to prevent XSS
    safe_name = escape(name)

    # Specify encoding in the HTTP header
    response = make_response(f"<h1>Hello, {safe_name}!</h1>")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    return response


@app.route('/submit', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Limit submissions to 5 per minute
def submit():
    """
    Handles form submissions with CSRF protection using Flask-WTF.
    """
    form = MyForm()
    if form.validate_on_submit():
        safe_data = escape(form.data.data)

        # Log successful submission
        logger.info(f"Successful form submission with data: {safe_data}")

        return f"Data received: {safe_data}"
    else:
        # Log form validation errors
        logger.warning(f"Form validation errors: {form.errors}")
        return render_template('submit_error.html', form=form), 400


def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    allowed_hosts = [ref_url.netloc]  # Add any allowed subdomains here
    return test_url.scheme in ('http', 'https') and test_url.netloc in allowed_hosts


@app.route('/redirect')
def redirect_view():
    """
    Redirects to a URL provided in the 'next' parameter, but only if it's safe.
    """
    next_url = request.args.get('next')
    if next_url and is_safe_url(next_url):
        return redirect(next_url)
    else:
        logger.warning(f"Unsafe redirect attempted to: {next_url}")
        return "Invalid redirect URL.", 400


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit errors."""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return "Rate limit exceeded. Please try again later.", 429


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

