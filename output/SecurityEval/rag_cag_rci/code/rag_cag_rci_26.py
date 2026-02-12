from flask import Response, request, Flask
from werkzeug.datastructures import Headers
import re
import secrets
from flask import session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a strong secret key

ALLOWED_CONTENT_TYPES = ["application/json", "text/xml", "text/plain", "application/pdf"]  # Example allowlist

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/route')
def route():
    '''
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    '''
    content_type = request.args.get('content_type')

    if not content_type:
        return Response("Content-Type parameter is missing.", status=400)

    # Validate content_type against the allowlist
    if content_type not in ALLOWED_CONTENT_TYPES:
        return Response("Invalid Content-Type.", status=400)

    # Sanitize the content_type (more robust than just allowlist in some cases)
    # Example:  Remove any characters that are not alphanumeric or slashes
    sanitized_content_type = re.sub(r'[^\w\/\-\+]+', '', content_type)

    # Encoding specification
    headers = Headers()
    headers.add('Content-Type', sanitized_content_type + '; charset=utf-8')  # Specify encoding

    response = Response("Content-Type set.", headers=headers)

    # Set HttpOnly cookie
    session['example_data'] = 'some_value' # Example session data
    response.set_cookie('session_cookie', 'cookie_value', httponly=True, secure=True, samesite='Lax') # Secure and HttpOnly

    return response

# Example route demonstrating CSRF protection using double-submit cookie method
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        return f'''
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <input type="text" name="data">
                <button type="submit">Submit</button>
            </form>
        '''
    elif request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return Response("CSRF token is invalid.", status=400)

        data = request.form.get('data')
        # Sanitize and validate data before processing
        sanitized_data = re.sub(r'[^\w\s]+', '', data) # Example sanitization
        return f"Data received: {sanitized_data}"

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Enforce HTTPS (for production, use proper certificates)

