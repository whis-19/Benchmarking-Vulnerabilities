import requests
from flask import Flask, request, jsonify
import json
import os

app = Flask(__name__)

# Securely retrieve the GitHub API token from an environment variable
GITHUB_API_TOKEN = os.environ.get("GITHUB_API_TOKEN")

if not GITHUB_API_TOKEN:
    print("Warning: GITHUB_API_TOKEN environment variable not set.  API requests may be rate-limited.")


@app.route("/get_github_info", methods=['GET'])  # Explicitly specify the method
def github_info():
    """
    Get the GitHub username from the request and return the GitHub info of the user using this URL: https://api.github.com/users/{username}.

    :return: GitHub info of the user
    """
    username = request.args.get("username")  # Use request.args for GET parameters

    if not username:
        return jsonify({"error": "Username is required"}), 400  # Return a proper error response

    url = f"https://api.github.com/users/{username}"

    headers = {}
    if GITHUB_API_TOKEN:
        headers["Authorization"] = f"token {GITHUB_API_TOKEN}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        github_data = response.json()
        return jsonify(github_data), 200  # Return the data as JSON with a 200 OK status

    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return jsonify({"error": f"Failed to retrieve GitHub information: {str(e)}"}), 500  # Return a 500 error

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON response from GitHub API"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

