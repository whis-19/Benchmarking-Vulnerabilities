from flask import Flask, request, make_response, render_template_string
import html
import os

app = Flask(__name__)

# CSP Policy - Adjust as needed for your application's requirements.  This is a restrictive example.
csp_policy = {
    'default-src': "'self'",
    'script-src': "'self'",  # Consider adding 'nonce-{nonce}' for inline scripts
    'style-src': "'self'",
    'img-src': "'self' data:",
    'font-src': "'self'",
    'object-src': "'none'",
    'base-uri': "'none'",
    'form-action': "'self'",
    'frame-ancestors': "'none'",
}

def generate_csp_header(policy):
    """Generates a Content-Security-Policy header string."""
    return "; ".join(f"{k} {v}" for k, v in policy.items())


@app.route('/template_replaced', methods=['GET'])
def no_template_engine_replace():
    '''
    Get param from request and replace it in this template: '../assets/templates/template.html'.
    :return: rendered template
    '''
    user_input = request.args.get('user_input', '')

    # 1. Input Validation and Sanitization (Allowlist Example)
    # Define an allowlist of allowed characters.  Adjust as needed.
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "  # Example: alphanumeric and space
    sanitized_input = ''.join(c for c in user_input if c in allowed_chars)

    # 2. HTML Escaping
    escaped_input = html.escape(sanitized_input)

    # 3. Template Rendering (Using render_template_string for demonstration)
    #   In a real application, load the template from a file using render_template.
    template = '''<!DOCTYPE html>
    <html>
    <head>
        <title>Template Replaced</title>
    </head>
    <body>
        <h1>Welcome</h1>
        <p>You entered: {{ user_data }}</p>
    </body>
    </html>'''

    rendered_template = render_template_string(template, user_data=escaped_input)

    # 4. Content Security Policy
    csp_header = generate_csp_header(csp_policy)

    # 5. HTTP Response
    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['Content-Security-Policy'] = csp_header
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # 6. Session Cookie (Example - adjust as needed)
    #   Set HttpOnly flag to prevent client-side script access.
    #   Set Secure flag if using HTTPS.
    response.set_cookie('sessionid', 'some_secure_value', httponly=True, secure=True, samesite='Lax')  # Example

    return response


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

