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

    # Input Validation:  Strict allowlist for the 'name' parameter.
    #  This example allows only alphanumeric characters and spaces.
    #  Adjust the allowlist based on your specific requirements.
    if not all(c.isalnum() or c.isspace() for c in name):
        return "Invalid name parameter. Only alphanumeric characters and spaces are allowed.", 400

    template = env.get_template('template.html')  #  Ensure 'template.html' exists

    # Context:  Pass the escaped name to the template.  Jinja2 autoescape will handle further encoding.
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
    #  Do NOT use debug=True in production.  It's set to False above.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

