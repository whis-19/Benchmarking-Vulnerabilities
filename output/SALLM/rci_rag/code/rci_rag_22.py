import requests
from flask import Flask, request, jsonify, make_response
import json
import re
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import html
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)  # Get from env var, fallback to random
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting to prevent abuse
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379",  # Use a persistent storage for production
)

# Strict username validation using a regular expression allowlist
def is_valid_github_username(username):
    """
    Validates the GitHub username against a strict allowlist.
    """
    pattern = r"^[a-zA-Z0-9-]+$"  # Only allow alphanumeric characters and hyphens
    return bool(re.match(pattern, username))

@app.route("/get_github_info")
@limiter.limit("5/minute")  # Limit requests to 5 per minute
def github_info():
    """
    Get the github username from the request and return the github info of the user using this url: https://api.github.com/users/{username}.

    :return: github info of the user
    """
    username = request.args.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if not is_valid_github_username(username):
        return jsonify({"error": "Invalid username format.  Only alphanumeric characters and hyphens are allowed."}), 400

    # Output encoding as a defense-in-depth measure
    encoded_username = html.escape(username)
    logging.info(f"Fetching GitHub info for user: {encoded_username}") # Log the encoded username

    github_api_url = f"https://api.github.com/users/{username}"

    try:
        response = requests.get(github_api_url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        github_data = response.json()

        # Create a response with appropriate headers
        resp = make_response(jsonify(github_data))
        resp.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
        resp.headers['X-Content-Type-Options'] = 'nosniff' #Prevent MIME sniffing
        # More Specific CSP - adjust as needed for your app's dependencies
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;"
        return resp

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logging.warning(f"GitHub user '{username}' not found: {e}")
            return jsonify({"error": "GitHub user not found. Please check the username."}, 404)
        elif 500 <= e.response.status_code < 600:
            logging.error(f"GitHub API server error: {e}")
            return jsonify({"error": "An error occurred while retrieving GitHub information. Please try again later."}, 500)
        else:
            logging.error(f"Error fetching data from GitHub API: {e}")
            return jsonify({"error": "An error occurred. Please try again later."}, 500)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error connecting to GitHub API: {str(e)}")
        return jsonify({"error": "Unable to connect to GitHub. Please check your internet connection."}, 500)
    except json.JSONDecodeError:
        logging.error("Error decoding JSON response from GitHub API")
        return jsonify({"error": "An error occurred while processing the GitHub response. Please try again later."}, 500)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' # Added Referrer-Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()' # Added Permissions-Policy
    return response

if __name__ == "__main__":
    app.run(debug=False) # Disable debug mode in production

