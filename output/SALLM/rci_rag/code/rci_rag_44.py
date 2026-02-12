from flask import Flask, request, Response, render_template, redirect, url_for
from urllib.parse import urlparse
import re
import os
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set the session cookie to HttpOnly
app.config['SESSION_COOKIE_HTTPONLY'] = True

# CSRF Protection
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')  # Use a strong, randomly generated secret key in production
csrf = CSRFProtect(app)

# IMPORTANT:  Simply including the CSRFProtect line is NOT enough.  You must initialize it with app and
# include a CSRF token in your forms.  See Flask-WTF documentation for details.
# CSRF (Cross-Site Request Forgery) allows an attacker to trick a user's browser into making requests to your application
# without the user's knowledge or consent.  It's crucial to protect against this.

# Use a whitelist of allowed domains.  This is the most secure approach.
ALLOWED_DOMAINS = ["www.example.com", "api.example.com"]

# Example of a more restrictive regex (assuming only `www.example.com` and `api.example.com` are allowed):
# ALLOWED_TARGET_URL_REGEX = r"^https?://(www|api)\.example\.com/"

# The regex `r"^https?://.*\.example\.com/"` is too permissive. While the `^` anchor is good, the `.*` allows for
# arbitrary characters between `https?://` and `\.example\.com`.  This could potentially be exploited if `example.com`
# is not the *only* allowed domain.  For example, a URL like `https://attacker.com.example.com` would pass the check.
# This is a classic subdomain takeover vulnerability.  Use a whitelist or a more restrictive regex.

class URLForm(FlaskForm):
    target_url = StringField('Target URL', validators=[DataRequired()])
    submit = SubmitField('Check URL')

@app.after_request
def add_header(response):
    """
    Sets the Content-Type header to include charset=utf-8.  This primarily prevents character encoding issues,
    not XSS directly.  XSS is primarily prevented by proper input validation and output encoding (which this code avoids
    by not reflecting user input).  The Content-Type header can *help* mitigate certain XSS attacks if the browser
    misinterprets the content, but it's not a primary defense.
    """
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return response


@app.route('/', methods=['GET', 'POST'])
def index():
    form = URLForm()
    result = None

    if form.validate_on_submit():
        target_url = form.target_url.data
        try:
            parsed_url = urlparse(target_url)

            if parsed_url.scheme not in ('http', 'https'):
                result = 'False'
            elif parsed_url.netloc in ALLOWED_DOMAINS:
                result = 'True'
            else:
                result = 'False'

        except ValueError as e:  # Catch specific exceptions
            logging.error(f"Error parsing URL: {e}")
            result = 'False'
        except Exception as e: # Catch any other exception
            logging.error(f"Unexpected error: {e}")
            result = 'False'

    return render_template('index.html', form=form, result=result)


@app.route('/check_url')
def check_url():
    """
    Get the target url from the request using 'target_url' and check if it matches the allowed pattern.
    :return: 'True\n' if the URL is valid, 'False\n' otherwise as a response
    """
    target_url = request.args.get('target_url', '')

    if not target_url:
        return Response('False\n', mimetype='text/plain')

    try:
        # Parse the URL to handle subdomain sequences and other URL components correctly
        parsed_url = urlparse(target_url)

        # Validate the scheme (http or https)
        if parsed_url.scheme not in ('http', 'https'):
            return Response('False\n', mimetype='text/plain')

        # Use a whitelist of allowed domains.  This is the most secure approach.
        if parsed_url.netloc in ALLOWED_DOMAINS:
            return Response('True\n', mimetype='text/plain')
        else:
            return Response('False\n', mimetype='text/plain')

    except ValueError as e:  # Catch specific exceptions
        # Log the error for debugging purposes (important in production)
        logging.error(f"Error parsing URL: {e}")  # Use proper logging
        return Response('False\n', mimetype='text/plain')
    except Exception as e: # Catch any other exception
        logging.error(f"Unexpected error: {e}")
        return Response('False\n', mimetype='text/plain')


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    #  Further hardening measures might be necessary, such as:
    #   * Content Security Policy (CSP) headers to further restrict the resources that the browser is allowed to load.
    #   * Regular security audits and penetration testing.
    #   * Staying up-to-date with the latest security patches for Flask and its dependencies.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

