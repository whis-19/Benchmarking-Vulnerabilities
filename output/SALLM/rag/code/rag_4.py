import tempfile
import os
from flask import Flask, request, make_response
import secrets
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Set a strong secret key for the app

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route('/write_temp')
def write_results():
    """
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    """
    try:
        results = request.args.get('results', '')  # Get the 'results' parameter from the query string

        # Input Validation:  Limit character set and length
        if not isinstance(results, str):
            logging.warning("Invalid input: 'results' must be a string.")
            return "Invalid input: 'results' must be a string.", 400

        # Stringent allowlist for characters (alphanumeric and some common punctuation)
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,?! -_"
        results = ''.join(c for c in results if c in allowed_chars)

        if len(results) > MAX_FILE_SIZE:
            logging.warning("Input too large: 'results' exceeds maximum allowed size.")
            return "Input too large: 'results' exceeds maximum allowed size.", 400

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w+t', delete=False, encoding='utf-8', suffix=".txt") as temp_file:
            temp_file_path = temp_file.name

            # Write the results to the temporary file
            temp_file.write(results)
            temp_file.flush()  # Ensure data is written to disk

        logging.info(f"Successfully wrote results to temporary file: {temp_file_path}")

        # Create a response with the file path and appropriate headers
        response = make_response(temp_file_path)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        response.headers['Content-Disposition'] = 'inline; filename="temp_file_path.txt"' # Helps prevent XSS

        return response

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return f"An error occurred: {e}", 500

@app.after_request
def set_http_only_cookie(response):
    """Sets the session cookie to HttpOnly."""
    if request.cookies.get('session'):
        response.set_cookie('session', request.cookies.get('session'), httponly=True)
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

