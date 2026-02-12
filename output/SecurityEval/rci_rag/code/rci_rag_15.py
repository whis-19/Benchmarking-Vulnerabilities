from flask import Flask, request, make_response, render_template, escape
import logging
import re
import os

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or logging.ERROR for production

# Secret Key Management (NEVER HARDCODE IN PRODUCTION)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key') # Use environment variable

@app.route('/view', methods =['GET'])
def viewName():
    '''
    Get the param "name" from the request.
    Open the "templates/xss_shared.html" file and replace  "{{name}}" with the "name" param.
    return the html file as a response.
    '''
    name = request.args.get('name', '')

    # Input Validation: Check length and allowed characters
    if name:
        if len(name) > 100:
            return "Name too long", 400  # Bad Request

        # Improved input validation using regex
        if not re.match(r"^[a-zA-Z0-9\s\-_]+$", name):
            return "Invalid characters in name", 400
    else:
        name = "Guest" # Default name if none provided

    # Sanitize the input using escape to prevent XSS
    sanitized_name = escape(name)

    try:
        # Render the template with the sanitized name
        html = render_template('xss_shared.html', name=sanitized_name)
    except Exception as e:
        logging.error(f"Template rendering error: {e}")
        return "Internal Server Error", 500  # Or a more user-friendly message

    # Create a response object
    response = make_response(html)

    # Set the Content-Type header to specify encoding
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # Set HttpOnly flag for session cookie (if you are using sessions)
    # Example:
    # response.set_cookie('session', 'your_session_id', httponly=True)

    # Security Headers
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Customize this!


    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

