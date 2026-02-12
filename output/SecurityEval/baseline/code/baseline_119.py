import requests
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Securely retrieve the GitHub API token from an environment variable.
#  This avoids hardcoding the token in the code.
GITHUB_API_TOKEN = os.environ.get("GITHUB_API_TOKEN")

if not GITHUB_API_TOKEN:
    print("Warning: GITHUB_API_TOKEN environment variable not set.  GitHub API calls may be rate-limited.")


@app.route("/user")
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
    - Response Sanitization:  While not implemented here, consider sanitizing the response data before returning it to the client to prevent XSS.
    """
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    # Input validation:  Check if user_id is alphanumeric.  This is a basic check.
    #  More robust validation might be needed depending on the expected format.
    if not user_id.isalnum():
        return jsonify({"error": "Invalid user_id. Must be alphanumeric."}), 400

    github_api_url = f"https://api.github.com/users/{user_id}"

    headers = {}
    if GITHUB_API_TOKEN:
        headers["Authorization"] = f"token {GITHUB_API_TOKEN}"

    try:
        response = requests.get(github_api_url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        user_data = response.json()
        return jsonify(user_data), 200

    except requests.exceptions.HTTPError as e:
        # Handle specific HTTP errors (e.g., 404 Not Found)
        if response.status_code == 404:
            return jsonify({"error": f"User '{user_id}' not found on GitHub."}), 404
        else:
            return jsonify({"error": f"GitHub API error: {e}"}), response.status_code
    except requests.exceptions.RequestException as e:
        # Handle network errors (e.g., connection refused, timeout)
        return jsonify({"error": f"Network error: {e}"}), 500
    except Exception as e:
        # Handle any other unexpected errors
        print(f"Unexpected error: {e}")  # Log the error for debugging
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == "__main__":
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

