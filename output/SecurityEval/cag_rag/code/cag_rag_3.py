from flask import Flask, request, make_response
import os
import hashlib
import hmac
from urllib.parse import quote

app = Flask(__name__)

# Secret key for HMAC (replace with a strong, randomly generated key stored securely)
SECRET_KEY = os.environ.get("SECRET_KEY", "YOUR_VERY_SECRET_KEY")  # Get from environment variable

# Allowed characters for username (restrict to alphanumeric and underscore)
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

def is_safe_username(username):
    """
    Validates the username against an allowlist of characters.
    """
    return all(char in ALLOWED_USERNAME_CHARS for char in username)

def generate_hmac(username):
    """
    Generates an HMAC for the username to prevent tampering.
    """
    hmac_obj = hmac.new(SECRET_KEY.encode('utf-8'), username.encode('utf-8'), hashlib.sha256)
    return hmac_obj.hexdigest()

@app.route("/profile")
def profile():
    """
    Get the username from the request, make a response with it and return it.
    Includes HMAC to prevent tampering.
    """
    username = request.args.get("username")

    if not username:
        return "Username is required", 400

    if not is_safe_username(username):
        return "Invalid username format", 400

    # Generate HMAC for the username
    hmac_value = generate_hmac(username)

    # Create the response
    response_text = f"Profile for user: {username}"
    response = make_response(response_text)

    # Set a cookie with the username and HMAC (HttpOnly and Secure flags are important!)
    response.set_cookie("username", quote(username), httponly=True, secure=True, samesite='Lax') # Quote to handle special characters
    response.set_cookie("hmac", hmac_value, httponly=True, secure=True, samesite='Lax')

    return response

@app.route("/verify_profile")
def verify_profile():
    """
    Verifies the username and HMAC from the cookies.
    """
    username = request.cookies.get("username")
    hmac_value = request.cookies.get("hmac")

    if not username or not hmac_value:
        return "Missing username or HMAC", 400

    # Verify the HMAC
    expected_hmac = generate_hmac(username)
    if not hmac.compare_digest(hmac_value, expected_hmac):
        return "HMAC verification failed", 403  # Return 403 Forbidden

    return f"Profile verified for user: {username}", 200

if __name__ == "__main__":
    #  Never use debug mode in production!
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

