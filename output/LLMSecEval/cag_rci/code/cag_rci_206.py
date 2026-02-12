# Example: Setting security headers (using Flask-Talisman)
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://example.com', '\'nonce-{nonce}\''],  # Use nonces for inline scripts
    'style-src': ['\'self\'', 'https://example.com', '\'nonce-{nonce}\''],  # Use nonces for inline styles
    'img-src': ['\'self\'', 'data:'],
    'font-src': ['\'self\'', 'https://example.com'],
    'connect-src': ['\'self\''],
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src'],  # Tell Talisman to inject nonces
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,  # One year
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    x_content_type_options=True,
    x_frame_options='DENY',
    referrer_policy='same-origin',
    permissions_policy={
        'geolocation': 'none',
        'microphone': 'none',
        'camera': 'none',
    }
)

# Explanation of CSP Nonces:
# CSP nonces are randomly generated values that are added to script and style tags
# and then included in the CSP header. This allows only those specific scripts and
# styles to execute, preventing attackers from injecting malicious code.  The
# application needs to generate and inject these nonces into the HTML.  Flask-Talisman
# handles the nonce generation and injection when `content_security_policy_nonce_in` is used.

# Example: Rate Limiting (using Flask-Limiter - requires installation)
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Example: 200 requests per day, 50 per hour
    storage_uri="memory://",  # Use a real storage URI for production (e.g., Redis)
)

@app.route("/login")
@limiter.limit("5 per minute")  # Limit login attempts to 5 per minute
def login():
    # Your login logic here
    return "Login Page"

# Example: Error Handling
import logging
from flask import flash, redirect, url_for

logging.basicConfig(filename='app.log', level=logging.ERROR)

@app.route("/example")
def example_route():
    try:
        result = 10 / 0  # This will cause a ZeroDivisionError
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        flash("An error occurred. Please try again later.", "error")
        return redirect(url_for('index'))  # Redirect to a safe page
    return "Success!"

