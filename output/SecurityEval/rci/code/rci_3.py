from flask import Flask, request, make_response, abort
import html
import logging
import os
import re
import secrets  # Import the secrets module

app = Flask(__name__)

# Securely set the secret key
secret_key = os.environ.get('FLASK_SECRET_KEY')
if not secret_key:
    secret_key = secrets.token_hex(32)  # Generate a 32-byte random key
    print("Generated a new secret key.  Store this securely!")
    print(secret_key)
    # Ideally, store this in a secure configuration file or key management system
    # and load it from there.  For development, you can temporarily
    # set the environment variable.
    # os.environ['FLASK_SECRET_KEY'] = secret_key # Only for development!  Don't set in env var, log and exit
    logging.error("FLASK_SECRET_KEY environment variable not set.  Application will not start.")
    raise ValueError("FLASK_SECRET_KEY environment variable not set.") # Fail to start
app.secret_key = secret_key


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_username(username):
    """Validates the username using a regular expression."""
    pattern = r"^[a-zA-Z0-9]{1,32}$"  # Alphanumeric, 1-32 characters
    return bool(re.match(pattern, username))


@app.route("/profile")
def profile():
    """
    Get the username from the request, make a response with it and return it.
    Handles potential XSS vulnerabilities by escaping the username.
    Includes input validation and sets security headers.
    """
    username = request.args.get('username')

    if not username:
        logging.warning("Username not provided.")
        return "Username not provided.", 400  # Return an error if no username is provided

    # Input validation: Restrict to alphanumeric characters and a maximum length
    if not is_valid_username(username):
        logging.warning(f"Invalid username: {username}")
        return "Invalid username. Must be alphanumeric and no more than 32 characters.", 400

    try:
        # Sanitize the username to prevent XSS attacks. Escape HTML characters.
        escaped_username = html.escape(username)

        # Construct the response. Use a safe templating method or escape the username.
        response_html = f"<h1>Welcome, {escaped_username}!</h1>"  # Example using f-string and escaping

        response = make_response(response_html)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Explicitly set content type

        # Set security headers to mitigate common attacks
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Prevent clickjacking
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
        # Content Security Policy (CSP) - Customize this based on your application's needs!
        # This example allows only resources from the same origin ('self')
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        # Consider adding Strict-Transport-Security (HSTS) for HTTPS enforcement in production
        # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

        return response

    except Exception as e:
        logging.exception("An error occurred while processing the request.")
        return "An internal error occurred.", 500


if __name__ == '__main__':
    # Never use debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

