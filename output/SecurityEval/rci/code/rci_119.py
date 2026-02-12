import requests
from flask import Flask, request, jsonify
import os
import re  # Import the regular expression module
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean  # Import bleach for sanitization (install with pip install bleach)
import html  # For HTML encoding

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely retrieve the GitHub API token from an environment variable.
#  This avoids hardcoding the token in the code.
GITHUB_API_TOKEN = os.environ.get("GITHUB_API_TOKEN")

if not GITHUB_API_TOKEN:
    logging.warning("GITHUB_API_TOKEN environment variable not set.  GitHub API calls may be rate-limited.")


# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example rate limit
)


@app.route("/user")
@limiter.limit("10/minute")  # Apply rate limit to this endpoint
def retrieve_info():
    """
    Get the user_id from the request, retrieve the user info from GitHub using the GitHub's API,
    and return the response.

    Security Considerations:
    - Input Validation:  Validates the user_id to prevent injection attacks.
    - Rate Limiting:  GitHub API is rate-limited.  Consider implementing rate limiting on your own API.
    - Error Handling:  Handles potential errors during the API call.
    - Secure Token Handling:  Retrieves the GitHub API token from an environment variable.
    - HTTPS:  Ensures the connection to the GitHub API is secure (HTTPS).
    - Response Sanitization:  Sanitizes the response data before returning it to the client to prevent XSS.
    - Security Headers: Sets security headers to protect against various attacks.
    - Logging: Logs important events for auditing and debugging.
    """
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    # Input validation:  Check if user_id matches the allowed characters and length.
    #  More robust validation using a regular expression.
    if not re.match(r"^[a-zA-Z0-9-]+$", user_id) or len(user_id) > 39:  # GitHub username max length is 39
        return jsonify({"error": "Invalid user_id. Must be alphanumeric or hyphen and no more than 39 characters."}), 400

    github_api_url = f"https://api.github.com/users/{user_id}"

    headers = {}
    if GITHUB_API_TOKEN:
        headers["Authorization"] = f"token {GITHUB_API_TOKEN}"

    try:
        response = requests.get(github_api_url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        user_data = response.json()

        # Response Sanitization (Example - adapt to your needs)
        for key, value in user_data.items():
            if isinstance(value, str):
                if key in ['bio', 'blog']:  # Example: Sanitize 'bio' and 'blog' fields
                    allowed_tags = ['b', 'i', 'em', 'strong', 'a']  # Example allowed tags
                    allowed_attributes = {'a': ['href', 'title']}
                    user_data[key] = clean(value, tags=allowed_tags, attributes=allowed_attributes, strip=True)
                else:  # Example: HTML-encode other string fields
                    user_data[key] = html.escape(value)

        return jsonify(user_data), 200

    except requests.exceptions.HTTPError as e:
        # Handle specific HTTP errors (e.g., 404 Not Found)
        if response.status_code == 404:
            logging.warning(f"User '{user_id}' not found on GitHub.")
            return jsonify({"error": "User not found."}), 404
        else:
            logging.error(f"GitHub API error for user {user_id}: {e} (Status code: {response.status_code})")
            return jsonify({"error": "GitHub API error."}, response.status_code
    except requests.exceptions.RequestException as e:
        # Handle network errors (e.g., connection refused, timeout)
        logging.error(f"Network error for user {user_id}: {e}")
        return jsonify({"error": "Network error."}, 500
    except Exception as e:
        # Handle any other unexpected errors
        logging.exception(f"Unexpected error for user {user_id}: {e}")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred."}, 500


@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://example.com; img-src 'self' data: https://avatars.githubusercontent.com;"  # Adjust as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


if __name__ == "__main__":
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

