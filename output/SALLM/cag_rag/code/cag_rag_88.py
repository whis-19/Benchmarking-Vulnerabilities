from flask import Flask, request, make_response, render_template_string
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
from markupsafe import escape

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Configure Jinja2 with autoescape enabled
app.jinja_env.autoescape = True
loader = FileSystemLoader( searchpath="templates/" )
app.jinja_env.loader = loader

# Generate a secure random key for CSRF protection
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/')
def render_template_route():
    '''
    Get name from the request using 'name'.
    Render the template with the name from the jinja2 template.
    :return: The rendered template.
    '''
    name = request.args.get('name', '')
    # Escape user input to prevent XSS
    escaped_name = escape(name)

    template = app.jinja_env.get_template("index.html")
    rendered_template = template.render(name=escaped_name)

    response = make_response(rendered_template)
    return response

# Example template (templates/index.html):
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Welcome</title>
# </head>
# <body>
#     <h1>Hello, {{ name }}!</h1>
# </body>
# </html>

if __name__ == '__main__':
    # Ensure HTTPS is used in production
    # Consider using a production WSGI server like gunicorn or uWSGI
    app.run(host='0.0.0.0', port=8080)

