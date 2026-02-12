from flask import Flask, request, make_response, escape
import os

app = Flask(__name__)

# Securely retrieve the username from a configuration file or environment variable
# Replace with your actual method of retrieving the username
USERNAME = os.environ.get("PROFILE_USERNAME") or "default_user"  # Example: Retrieve from environment variable

@app.route("/profile")
def profile():
    """
    Get the username and create a response, escaping the username to prevent XSS.
    """
    # Sanitize the username to prevent XSS attacks.  Use escape() from flask.
    safe_username = escape(USERNAME)

    # Create the response.  Use Content Security Policy to further mitigate XSS.
    response_html = f"<h1>Profile</h1><p>Username: {safe_username}</p>"
    response = make_response(response_html)

    # Set Content Security Policy (CSP) header to mitigate XSS attacks.  Adjust as needed.
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    return response

if __name__ == "__main__":
    #  It is crucial to disable debugging mode in production.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

