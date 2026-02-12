import os
from flask import Flask, request, make_response, render_template, escape
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Set HttpOnly flag for session cookie (if using sessions)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Initialize Jinja2 environment with autoescape enabled (default)
env = Environment(loader=FileSystemLoader('.'), autoescape=True)


def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request and returns a response.

    Args:
        env: The Jinja2 environment.

    Returns:
        A Flask response object.
    """
    name = request.args.get('name', '')

    # Input Validation:  Strict allowlist for 'name' parameter.  Only allow alphanumeric and spaces.
    if not all(c.isalnum() or c.isspace() for c in name):
        return "Invalid name parameter. Only alphanumeric characters and spaces are allowed.", 400

    template = env.get_template('template.html')  # Ensure template exists and is properly secured.

    # Context:  Escape the name parameter before rendering to prevent XSS.  Although autoescape is enabled, explicit escaping adds a layer of defense.
    rendered_template = template.render(name=escape(name))

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response


@app.route('/')
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(env)


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

