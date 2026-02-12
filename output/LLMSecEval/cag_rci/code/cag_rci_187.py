import os
import secrets
from flask import Flask, render_template_string, request
from flask_talisman import Talisman
import logging
import json

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or logging.ERROR for production

#  Important:  Set a strong secret key!  Store this securely (e.g., environment variable).
# Generate a secret key (only do this once and store it securely)
# secret_key = secrets.token_hex(32)
# print(f"Generated secret key: {secret_key}") # Print it once, then remove this line!

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or 'INSECURE_DEVELOPMENT_KEY' # NEVER use 'INSECURE_DEVELOPMENT_KEY' in production

#  Disable debug mode in production!
app.debug = False  # Ensure this is False in production!

csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'', # Add any CDNs or external sources here
    'style-src': '\'self\'',  # Add any CDNs or external sources here
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
    'frame-ancestors': '\'none\'',  # Prevent clickjacking
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src'], # Enable nonces for inline scripts/styles. Nonces are unique per request.
    force_https=True,  # Enforce HTTPS (if applicable).  Requires HTTPS termination at a reverse proxy.
    strict_transport_security=True,  # Enable HSTS
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True, # Submit your domain to hstspreload.org.  Inclusion can take several months.
    x_content_type_options=True,  # Prevent MIME sniffing
    referrer_policy='strict-origin-when-cross-origin',
    permissions_policy={  # Example Permissions-Policy
        'geolocation': 'none',
        'camera': 'none',
        'microphone': 'none',
    },
    content_security_policy_report_uri='/csp_report',  # Example CSP reporting (requires implementation). Consider using a dedicated service like Sentry for report analysis.
)


@app.route('/')
def hello_world():
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hello World</title>
    </head>
    <body>
        <h1>Hello, World!</h1>
        <script nonce="{{ csp_nonce() }}">
            console.log("Hello from inline script!");
        </script>
        <style nonce="{{ csp_nonce() }}">
            body { font-family: sans-serif; }
        </style>
    </body>
    </html>
    """
    return render_template_string(template)

# Example CSP reporting endpoint (requires implementation)
@app.route('/csp_report', methods=['POST'])
def csp_report():
    # Process the CSP report data
    try:
        report_data = request.get_json()
        logging.warning(f"CSP Violation Report: {report_data}") # Log the report
        # Store the report in a database or other persistent storage
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in CSP report: {e}")
        return "Invalid JSON", 400
    except Exception as e:
        logging.error(f"Error processing CSP report: {e}")
        return "Internal Server Error", 500
    return '', 204


if __name__ == '__main__':
    app.run(debug=True) #Remove debug=True for production

