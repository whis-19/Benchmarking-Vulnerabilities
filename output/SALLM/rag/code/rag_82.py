from flask import Flask, request, escape
import re
import os

app = Flask(__name__)

# Set HttpOnly flag for session cookie (if using sessions)
# This needs to be done when initializing the session, e.g.:
# app.config['SESSION_COOKIE_HTTPONLY'] = True

@app.after_request
def add_header(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/create_variable')
def create_variable():
    '''
    Get a string using 'str_var' from the request.
    Create a variable from the string.
    Return the variable.
    '''
    str_var = request.args.get('str_var', '')

    # Input Validation:  Strict allowlist for allowed characters.  
    #  This example allows only alphanumeric characters and underscores.
    #  Adjust the regex to fit your specific needs.  Crucially important.
    if not re.match(r'^[a-zA-Z0-9_]+$', str_var):
        return "Invalid input. Only alphanumeric characters and underscores are allowed.", 400

    # Input Sanitization: Escape special characters for HTML output.
    escaped_str_var = escape(str_var)

    #  Instead of creating a variable dynamically (which is inherently dangerous),
    #  return the sanitized input.  Dynamically creating variables from user input
    #  is a major security risk (code injection).  If you *absolutely* need to
    #  store this, consider using a dictionary with a fixed set of keys.

    return f"You entered: {escaped_str_var}"


if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

