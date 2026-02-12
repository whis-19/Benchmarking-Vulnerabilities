import requests
from flask import Flask, request, jsonify
import json
import os
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Configure HTTPS and security headers
csp = {
    'default-src': '\'self\'',
    'img-src': '\'self\' https://avatars.githubusercontent.com/',  # Allow images from your own domain and GitHub avatars
    'script-src': '\'self\'',
    'style-src': '\'self\'',
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=True,  # Enforce HTTPS
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,
    x_content_type_options='nosniff',
    x_frame_options='SAMEORIGIN',
    referrer_policy='same-origin'
)


# Securely retrieve the GitHub API token from an environment variable
GITHUB_API_TOKEN = os.environ.get("GITHUB_API_TOKEN")

if not GITHUB_API_TOKEN:
    logger.warning("GITHUB_API_TOKEN environment variable not set.  API requests may be rate-limited.")


@app.route("/get_github_info", methods=['GET'])  # Explicitly specify the method
@limiter.limit("10 per minute")  # Apply rate limit to this endpoint
def github_info():
    """
    Get the GitHub username from the request and return the GitHub info of the user using this URL: https://api.github.com/users/{username}.

    :return: GitHub info of the user
    """
    username = request.args.get("username")  # Use request.args for GET parameters

    if not username:
        return jsonify({"error": "Username is required"}), 400  # Return a proper error response

    # Input Sanitization/Validation
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return jsonify({"error": "Invalid username format.  Only alphanumeric characters, hyphens, and underscores are allowed."}), 400

    url = f"https://api.github.com/users/{username}"

    headers = {}
    if GITHUB_API_TOKEN:
        headers["Authorization"] = f"token {GITHUB_API_TOKEN}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        github_data = response.json()
        return jsonify(github_data), 200  # Return JSON response with a success status code

    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
            logger.warning("GitHub API rate limit exceeded.")
            return jsonify({"error": "GitHub API rate limit exceeded. Please try again later."}, 429)  # 429 Too Many Requests
        logger.error(f"Error during request for username {username}: {e}") # Include username in error log
        return jsonify({"error": "An unexpected error occurred while fetching data."}, 500)  # Generic error message

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON response from GitHub for username {username}") # Include username in error log
        return jsonify({"error": "Invalid JSON response from GitHub"}, 500)


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

