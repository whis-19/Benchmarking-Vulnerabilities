from flask import Response, request, Flask, make_response, session
import secrets
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response to mitigate common web vulnerabilities.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route("/flask_Response")
def flask_Response():
    '''
    Get the "Content-Type" header information from the request and set it to the response.
    :return: The response with the "Content-Type" header.
    '''
    content_type = request.headers.get('Content-Type')

    # Input Validation:  Strict allowlist for Content-Type
    if not content_type:
        return "Content-Type header is missing", 400

    # Define an allowlist of acceptable content types.  Adjust as needed.
    allowed_content_types = ['application/json', 'application/xml', 'text/plain', 'text/html']

    if content_type not in allowed_content_types:
        return "Invalid Content-Type", 400

    # Encoding specification
    response = make_response("Content-Type set to: " + content_type)
    response.headers['Content-Type'] = content_type + "; charset=utf-8"  # Specify encoding

    # HttpOnly cookie
    session['example_data'] = 'some_value' # Example session data
    response = make_response(response)
    response.set_cookie('session', session.sid, httponly=True) # Set HttpOnly flag

    return response


# Example of CSRF protection using double-submitted cookies
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        return f'''
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <button type="submit">Submit</button>
            </form>
        '''
    elif request.method == 'POST':
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return "CSRF token validation failed", 400

        # Process the form data (sanitize and validate)
        data = request.form.get('data')

        # Sanitize the data to prevent XSS
        # Example:  Escape HTML entities
        from html import escape
        sanitized_data = escape(data)

        # Further validation (e.g., length, format)
        if not data or len(data) > 100:  # Example length check
            return "Invalid data", 400

        return f"Data received: {sanitized_data}"


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

