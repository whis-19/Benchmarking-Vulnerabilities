from flask import Flask, request, make_response
import secrets
import os
import re  # For input validation
import json # For JSON validation

app = Flask(__name__)

# Set a secure, production-ready secret key.  Crucial for session management and CSRF protection.
# In a real deployment, this should be read from an environment variable or a secure configuration file.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    print("CRITICAL: FLASK_SECRET_KEY environment variable not set!  Exiting.")
    exit(1)  # Terminate the application if the secret key is missing

@app.route("/getcookie")
def getcookie():
    '''
    Get the cookie from the request using 'cookie' and set it as a cookie in the response.
    :return: The response with the cookie.
    '''
    cookie_value = request.args.get('cookie')  # Get the cookie value from the query parameter

    if cookie_value:
        # Input Validation:  Sanitize the cookie value to prevent XSS and other attacks.
        # This is a VERY basic example.  You should tailor the validation to your specific needs.

        # Example 1: Alphanumeric, underscores, and hyphens
        if not re.match(r"^[a-zA-Z0-9_-]+$", cookie_value):
            return "Invalid cookie value.  Only alphanumeric characters, underscores, and hyphens are allowed."

        # Example 2:  If the cookie value is expected to be an integer
        try:
            int(cookie_value)  # Try to convert to an integer
        except ValueError:
            return "Invalid cookie value.  Must be an integer."

        # Example 3: If the cookie value is expected to be a JSON string
        try:
            data = json.loads(cookie_value)
            # Further validation of the JSON data structure can be done here
            if not isinstance(data, dict):
                return "Invalid cookie value.  JSON must be a dictionary."
        except json.JSONDecodeError:
            return "Invalid cookie value.  Must be a valid JSON string."


        response = make_response("Cookie set successfully!")
        # Set the cookie with HttpOnly and Secure flags for enhanced security.
        # HttpOnly prevents client-side scripts from accessing the cookie, mitigating XSS attacks.
        # Secure ensures the cookie is only transmitted over HTTPS.
        response.set_cookie('mycookie', cookie_value, httponly=True, secure=True, samesite='Lax') # Added samesite

        # Example of setting a basic CSP header
        response.headers['Content-Security-Policy'] = "default-src 'self'"

        return response
    else:
        return "No cookie value provided in the request."


if __name__ == "__main__":
    #  Never run in production with debug=True.  It exposes sensitive information.
    #  Use a production WSGI server like Gunicorn or uWSGI.
    app.run(debug=False, host="0.0.0.0", port=5000)

