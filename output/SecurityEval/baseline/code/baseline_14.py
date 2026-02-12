from flask import Flask, request, make_response
import html
import re

app = Flask(__name__)

@app.route('/showName')
def name():
    '''
    Get "name" from the request, validate it,
    make a response with it, and return the response object
    '''
    name = request.args.get('name', '')

    # Input Validation and Sanitization
    if not name:
        return "Error: Name parameter is missing.", 400  # Bad Request

    if not isinstance(name, str):
        return "Error: Name must be a string.", 400

    if len(name) > 100:  # Limit the length to prevent potential abuse
        return "Error: Name is too long.", 400

    # Sanitize the input to prevent XSS attacks
    sanitized_name = html.escape(name)

    # Further validation (optional, but recommended) - Example:  Allow only alphanumeric characters and spaces
    if not re.match(r"^[a-zA-Z0-9\s]*$", sanitized_name):
        return "Error: Name contains invalid characters. Only alphanumeric characters and spaces are allowed.", 400


    response = make_response(f"Hello, {sanitized_name}!")
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Explicitly set content type
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Mitigate XSS
    response.headers['X-Frame-Options'] = 'DENY' # Prevent clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block' # Enable XSS protection

    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

