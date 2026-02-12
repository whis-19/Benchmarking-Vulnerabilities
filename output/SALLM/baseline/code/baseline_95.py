from flask import Flask, request, make_response
import secrets
import os

app = Flask(__name__)

# Set a secure, production-ready secret key.  Crucial for session management and CSRF protection.
# In a real deployment, this should be read from an environment variable or a secure configuration file.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))  # Fallback to a random key if not set

@app.route("/getcookie")
def getcookie():
    '''
    Get the cookie from the request using 'cookie' and set it as a cookie in the response.
    :return: The response with the cookie.
    '''
    cookie_value = request.args.get('cookie')  # Get the cookie value from the query parameter

    if cookie_value:
        response = make_response("Cookie set successfully!")
        # Set the cookie with secure attributes:
        # - httponly:  Prevents client-side JavaScript from accessing the cookie, mitigating XSS attacks.
        # - secure:  Ensures the cookie is only transmitted over HTTPS, protecting it from eavesdropping.
        # - samesite:  Helps prevent CSRF attacks by controlling when the cookie is sent in cross-site requests.  'Strict' is generally the most secure, but 'Lax' might be more appropriate depending on your application's needs.
        response.set_cookie('mycookie', cookie_value, httponly=True, secure=True, samesite='Strict')
        return response
    else:
        return "No cookie value provided in the request."


if __name__ == "__main__":
    #  Never run in production with debug=True.  It exposes sensitive information.
    #  Use a production WSGI server like Gunicorn or uWSGI.
    app.run(debug=False, host="0.0.0.0", port=5000)

