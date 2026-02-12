import os
from flask import Flask, request, make_response, render_template_string, redirect, url_for, session, render_template
from jinja2 import Environment, FileSystemLoader, select_autoescape
import re
from urllib.parse import quote
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta

app = Flask(__name__)

# Securely load the secret key from an environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set!")

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production (e.g., redis://)
)

# Initialize Jinja2 environment with autoescape enabled
template_dir = os.path.dirname(os.path.abspath(__file__))
env = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=select_autoescape(['html', 'xml'])  # Enable autoescaping
)


def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring proper sanitization.

    Args:
        env: The Jinja2 environment.

    Returns:
        A Flask response object with the rendered template.
    """
    name = request.args.get('name', '')

    # Input Validation:  Strict allowlist for 'name' parameter.  Only allow alphanumeric and spaces.
    if not re.match(r"^[a-zA-Z0-9\s]*$", name):
        # Handle invalid input appropriately.  Do NOT just pass it through.
        # Here, we return an error message.  Alternatively, you could sanitize
        # the input by removing invalid characters, but that might change the
        # intended meaning.  Returning an error is generally safer.
        return "Invalid name parameter. Only alphanumeric characters and spaces are allowed.", 400

    template = env.from_string("<h1>Hello, {{ name }}!</h1>")  # Use from_string for simple templates

    # Context:  Pass the sanitized name to the template.
    rendered_template = template.render(name=name)

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response


@app.route("/")
@limiter.limit("10/minute")  # Apply rate limiting to the home route
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(env)


@app.route("/set_session")
def set_session():
    """Sets a session cookie with HttpOnly and Secure flags, regenerates session ID."""
    session['example'] = 'session_value'
    session.permanent = True  # Make the session permanent
    app.permanent_session_lifetime = timedelta(minutes=30)  # Set session expiration time

    # Regenerate session ID after login or other sensitive operations
    session.regenerate()

    resp = redirect(url_for('home'))
    resp.set_cookie('session_cookie', 'cookie_value', httponly=True, secure=True, samesite='Lax')  # Set HttpOnly, Secure, and SameSite flags
    return resp


@app.route("/redirect")
def insecure_redirect():
    """Demonstrates an insecure redirect (for demonstration purposes only)."""
    # NEVER do this in production!  This is vulnerable to open redirect attacks.
    target = request.args.get('target')
    if target:
        # DO NOT DO THIS!  This is insecure.
        # return redirect(target)

        # Instead, use a whitelist of allowed destinations:
        allowed_destinations = {
            'home': url_for('home'),
            'set_session': url_for('set_session')
        }
        if target in allowed_destinations:
            return redirect(allowed_destinations[target])
        else:
            return "Invalid redirect target.", 400
    else:
        return "No redirect target specified.", 400


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"  # Adjust as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' #Enable HSTS
    return response


@app.errorhandler(429)
def ratelimit_handler(e):
    return "Rate limit exceeded. Please try again later.", 429


# Example form to demonstrate CSRF protection
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    form = MyForm()
    if form.validate_on_submit():
        session['name'] = form.name.data
        return redirect(url_for('form_success'))
    return render_template('form.html', form=form)

@app.route('/form_success')
def form_success():
    name = session.get('name', 'Guest')
    return f"Hello, {name}!"


if __name__ == "__main__":
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

