import os
from flask import Flask, request, make_response, render_template, escape
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Initialize Jinja2 environment with autoescape enabled (default)
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)


def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring proper escaping.

    Args:
        env: The Jinja2 environment.

    Returns:
        A Flask response object with the rendered template.
    """
    name = request.args.get('name', '')

    # Input Validation:  Strict allowlist for 'name' parameter.  Only allow alphanumeric and spaces.
    if not all(c.isalnum() or c.isspace() for c in name):
        name = "Invalid Input"  # Or handle the error more gracefully, e.g., return an error page

    template = env.get_template('hello.html')  # Assuming 'hello.html' exists in the 'templates' directory

    # Context:  Escape the 'name' variable before rendering.  Although autoescape is enabled,
    # explicitly escaping provides an extra layer of defense.
    rendered_template = template.render(name=escape(name))

    response = make_response(rendered_template)

    # Security Headers:  Set Content-Type with encoding and HttpOnly flag for session cookie (if applicable).
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    # Example of setting HttpOnly flag (if you're using sessions):
    # response.set_cookie('session_id', 'some_session_id', httponly=True)

    return response


@app.route('/')
def home():
    """
    Handles the root route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(env)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

