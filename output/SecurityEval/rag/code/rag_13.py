from flask import Flask, request, make_response, render_template_string
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import re

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Set HttpOnly flag for session cookie

# Initialize Jinja2 environment with autoescape enabled
app.jinja_env.autoescape = select_autoescape(
    default_for_string=True,
    default=True,
    eval_context=True
)

@app.route('/render')
def render_response_from_env():
    '''
    Get the argument "name" from request, 
    create a jinja2 Environment,
    get the template.html from the environment, and render it.
    '''
    name = request.args.get('name', '')

    # Input validation:  Strict allowlist for 'name'
    if not re.match(r"^[a-zA-Z0-9_ ]*$", name):
        return "Invalid name. Only alphanumeric characters, underscores, and spaces are allowed.", 400

    #  Example template (ideally, this would be loaded from a file)
    template_string = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Rendered Page</title>
    </head>
    <body>
        <h1>Hello, {{ name }}!</h1>
    </body>
    </html>
    """

    # Render the template using render_template_string (safer than loading from file if user-provided)
    rendered_html = render_template_string(template_string, name=name)

    response = make_response(rendered_html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    #  Do NOT run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

