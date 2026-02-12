from flask import Flask, request, make_response, render_template_string
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
from markupsafe import escape

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Configure Jinja2 with autoescape enabled
app.jinja_env.autoescape = True

#  Consider using a more robust CSRF protection mechanism like Flask-WTF
#  This example provides a basic implementation for demonstration purposes.
def generate_csrf_token():
    return os.urandom(24).hex()

@app.route('/', methods=['GET', 'POST'])
def render_template_route():
    '''
    Get name from the request using 'name'.
    Render the template with the name from the jinja2 template.
    :return: The rendered template.
    '''
    name = request.args.get('name', '')
    if request.method == 'POST':
        name = request.form.get('name', '')

    # Validate and sanitize the name input
    name = escape(name)  # Escape user input to prevent XSS

    # Generate a CSRF token for state-changing operations (e.g., POST requests)
    csrf_token = generate_csrf_token()

    # Create the template string directly in the code.  This avoids file system access
    # and potential path traversal vulnerabilities.
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Template</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'">
    </head>
    <body>
        <h1>Hello, {{ name }}!</h1>
        <form method="post">
            <label for="name">Enter your name:</label>
            <input type="text" id="name" name="name" value="{{ name }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """

    # Render the template with the escaped name and CSRF token
    rendered_template = render_template_string(template, name=name, csrf_token=csrf_token)

    # Create the response
    response = make_response(rendered_template)

    # Set Content Security Policy (CSP) header
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'"

    return response

if __name__ == '__main__':
    #  Never run with debug=True in production!
    app.run(host='0.0.0.0', port=5000)

