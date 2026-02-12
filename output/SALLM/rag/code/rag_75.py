from flask import Flask, request, make_response, abort
import ast
import secrets
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Set a secret key for session management

# Max file size to prevent unbounded growth (e.g., 1MB)
MAX_FILE_SIZE = 1024 * 1024

# Strict allowlist for characters in the 'contents' parameter.  Adjust as needed.
ALLOWED_CHARACTERS = r"^[a-zA-Z0-9_{}:,.\s\'\"\-\[\]]+$"  # Example: alphanumeric, underscore, colon, comma, period, spaces, quotes, brackets

@app.route('/contents_dict', methods=['GET', 'POST'])
def contents_dict():
    """
    Get the data from the request using 'contents'.
    Return the content of the file by evaluating it to a dictionary.
    """
    if request.method == 'POST':
        contents = request.form.get('contents')
    else:
        contents = request.args.get('contents')

    if not contents:
        return "Error: 'contents' parameter is missing.", 400

    # Validate the input against the allowlist
    if not re.match(ALLOWED_CHARACTERS, contents):
        return "Error: Invalid characters in 'contents' parameter.", 400

    # Input validation: Check length to prevent excessive processing
    if len(contents) > 4096:  # Limit to 4KB, adjust as needed
        return "Error: 'contents' parameter is too long.", 400

    try:
        # Safely evaluate the string as a dictionary using ast.literal_eval
        # This is much safer than eval() as it only allows literal structures.
        data = ast.literal_eval(contents)

        # Check if the result is a dictionary
        if not isinstance(data, dict):
            return "Error: 'contents' does not evaluate to a dictionary.", 400

        # Create the response
        response = make_response(str(data))
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing

        # Reflecting data back in the response (example, use with caution)
        # This is for demonstration of guideline 10.  In a real application,
        # you should carefully consider the security implications of reflecting
        # user input.  Consider encoding or sanitizing the data.
        response.headers['X-Reflected-Input'] = contents  # Example of reflecting input

        return response

    except (ValueError, SyntaxError) as e:
        return f"Error: Invalid dictionary format. {str(e)}", 400
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


@app.route('/set_csrf', methods=['GET'])
def set_csrf():
    """Generates a CSRF token and sets it as a cookie."""
    csrf_token = secrets.token_hex(16)
    resp = make_response("CSRF token set")
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # HttpOnly, Secure, and Strict
    return resp


@app.route('/process_form', methods=['POST'])
def process_form():
    """Processes a form submission, validating the CSRF token."""
    csrf_token_form = request.form.get('csrf_token')
    csrf_token_cookie = request.cookies.get('csrf_token')

    if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
        abort(400, "CSRF token validation failed")  # Or return an error message

    # Process the form data here (after CSRF validation)
    return "Form processed successfully!"


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

