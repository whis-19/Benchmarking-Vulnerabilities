import os
from flask import Flask, request, make_response, render_template, escape
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

#  Set the session cookie to HttpOnly
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Initialize Jinja2 environment with autoescape enabled (default, but explicit for clarity)
template_env = Environment(loader=FileSystemLoader('.'), autoescape=True)


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

    template = env.get_template('template.html')  # Assuming 'template.html' exists

    #  Context:  Pass the *escaped* name to the template.  Jinja2 autoescape should handle this, but we're being extra careful.
    rendered_template = template.render(name=escape(name))

    response = make_response(rendered_template)

    # Specify encoding in the HTTP header
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    return response


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        A Flask response object.
    """
    return render_response_from_env(template_env)


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It's a security risk.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

