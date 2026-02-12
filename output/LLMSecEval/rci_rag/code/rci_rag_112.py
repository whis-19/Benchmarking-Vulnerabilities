import os
from flask import Flask, request, make_response, render_template_string, redirect, url_for, session
from jinja2 import Environment, FileSystemLoader, select_autoescape
import re
from urllib.parse import quote
import logging

app = Flask(__name__)

# Securely retrieve the secret key from an environment variable
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable not set!")
# app.secret_key = os.urandom(24)  # Replace with a strong, randomly generated secret key that is stored securely!

# Initialize Jinja2 environment with autoescape enabled
template_dir = os.path.dirname(os.path.abspath(__file__))
env = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=select_autoescape(['html', 'xml'])  # Enable autoescaping
)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


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
    if len(name) > 100:
        logger.warning("Name parameter too long: %s", name)
        return "Name is too long.", 400

    # Consider using a Unicode-aware regex if internationalization is required: ^[\p{L}\p{N}\s]*$
    # The following regex is a simpler ASCII-only version.  Use the Unicode version if
    # your application needs to support international characters.
    # If your application needs to support international characters, use the Unicode regex:
    # if not re.match(r"^[\p{L}\p{N}\s]*$", name):
    if not re.match(r"^[a-zA-Z0-9\s]*$", name):
        # Handle invalid input appropriately.  Do NOT just pass it through.
        # Here, we return an error message.  Alternatively, you could sanitize
        # the input by removing invalid characters, but that might change the
        # intended meaning.  Returning an error is generally safer.
        logger.warning("Invalid name parameter: %s", name)
        return "Invalid name parameter. Only alphanumeric characters and spaces are allowed.", 400

    template = env.from_string("<h1>Hello, {{ name }}!</h1>")  # Use from_string for simple templates

    # Context:  Pass the sanitized name to the template.
    rendered_template = template.render(name=name)

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(env)


@app.route("/set_session")
def set_session():
    """Sets a session cookie with HttpOnly, Secure, and SameSite flags."""
    session['example'] = 'session_value'
    resp = redirect(url_for('home'))
    # Set HttpOnly, Secure, and SameSite flags for enhanced session security.
    # - HttpOnly: Prevents client-side JavaScript from accessing the cookie.
    # - Secure:  Ensures the cookie is only transmitted over HTTPS.
    # - SameSite:  Helps prevent CSRF attacks by controlling when the cookie is sent in cross-site requests.
    resp.set_cookie('session_cookie', 'cookie_value', httponly=True, secure=True, samesite='Strict')
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
            logger.info("Redirecting to: %s", target)
            return redirect(allowed_destinations[target])
        else:
            logger.warning("Invalid redirect target: %s", target)
            return "Invalid redirect target.", 400
    else:
        return "No redirect target specified.", 400


# CSRF Protection:
#
# Cross-Site Request Forgery (CSRF) is a type of attack where a malicious website,
# email, blog, instant message, or program causes a user's web browser to perform
# an unwanted action on a trusted site when the user is authenticated.
#
# For any application that handles forms or state-changing requests, CSRF protection
# is essential.
#
# Flask-WTF provides CSRF protection.  It works by adding a hidden field to each
# form that contains a unique token.  The server then verifies that the token is
# present and valid before processing the form.
#
# Example (Conceptual - Requires Flask-WTF setup):
#
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)
#
# @app.route('/form', methods=['POST'])
# @csrf.exempt  # Only exempt if absolutely necessary and understand the risks
# def form_submission():
#     # ... process the form ...
#     return "Form submitted successfully!"


if __name__ == "__main__":
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

