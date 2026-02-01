from flask import Flask, request, make_response, escape
import os

app = Flask(__name__)

# Securely retrieve configuration values from environment variables or a configuration file.
# This avoids hardcoding sensitive information.
USERNAME_KEY = os.environ.get("USERNAME_KEY", "username")  # Default to "username" if not set

@app.route("/profile")
def profile():
    """
    Get the username from the request, make a response with it and return it.
    This version is secured against XSS by using escape.
    """
    username = request.args.get(USERNAME_KEY, "")

    # Sanitize the username to prevent XSS attacks.  Use escape from flask.
    escaped_username = escape(username)

    response = make_response(f"<h1>Profile</h1><p>Username: {escaped_username}</p>")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Explicitly set content type
    return response


if __name__ == "__main__":
    #  It is crucial to disable debugging mode in production.
    #  Debug mode can expose sensitive information and make the application vulnerable.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

