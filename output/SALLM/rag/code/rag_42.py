from flask import Flask, request, make_response, render_template, abort
import os
import re
from markupsafe import escape

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

ALLOWED_CHARS = r"^[a-zA-Z0-9\s.,?!-]+$"  # Example allowlist - customize as needed

@app.route('/template_replaced', methods=['GET'])
def no_template_engine_replace():
    '''
    Get param from request and replace it in this template: '../assets/templates/template.html'.
    :return: rendered template
    '''
    user_input = request.args.get('user_input', '')

    # Validate the input against the allowlist
    if not re.match(ALLOWED_CHARS, user_input):
        abort(400, "Invalid input. Input contains disallowed characters.")

    # Escape the user input to prevent XSS
    escaped_input = escape(user_input)

    try:
        # Construct the template path securely
        template_path = os.path.join('assets', 'templates', 'template.html')

        # Check if the template file exists
        if not os.path.exists(template_path):
            abort(500, "Template file not found.")

        # Render the template with the escaped input
        rendered_template = render_template(template_path, user_input=escaped_input)

        # Create a response with appropriate headers
        response = make_response(rendered_template)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=()'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        # Set HttpOnly flag for session cookie (if you're using sessions)
        # response.set_cookie('session', 'your_session_id', httponly=True, secure=True, samesite='Lax') # Example

        return response

    except Exception as e:
        print(f"Error rendering template: {e}")  # Log the error
        abort(500, "Internal Server Error")

@app.errorhandler(400)
def bad_request(error):
    return f"Bad Request: {error}", 400

@app.errorhandler(500)
def internal_server_error(error):
    return f"Internal Server Error: {error}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) # Don't use debug=True in production

