import os
from typing import Dict, Any
from urllib.parse import quote

from bottle import Bottle, request, response, template, HTTPError

# Initialize Bottle application
app = Bottle()

# Securely load template directory from environment variable
TEMPLATE_PATH = os.environ.get("TEMPLATE_PATH", "./templates")
app.config['template_path'] = TEMPLATE_PATH

# Example template (stored in templates/hello.tpl)
# <% name = request.params.get('name', 'World') %>
# Hello {{name}}!

def render_response_from_env(env: Bottle) -> str:
    """
    Renders a template based on user input from the request, ensuring proper sanitization.

    Args:
        env: The Bottle application environment.

    Returns:
        A string containing the rendered template.
    """
    try:
        name = request.params.get('name', 'World')

        # Input Validation and Sanitization:  Strict allowlist for 'name'
        # This example allows only alphanumeric characters and spaces.
        # Adjust the allowlist based on your specific requirements.
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
        sanitized_name = "".join(c for c in name if c in allowed_chars)

        # URL-encode the sanitized name to prevent injection vulnerabilities
        encoded_name = quote(sanitized_name)

        # Get the template from the environment.  Assume 'hello.tpl' exists.
        try:
            rendered_template = template('hello.tpl', name=encoded_name)
        except Exception as e:
            # Handle template rendering errors gracefully.  Log the error.
            print(f"Template rendering error: {e}")
            response.status = 500
            return "Internal Server Error: Failed to render template."

        return rendered_template

    except Exception as e:
        # Catch any unexpected errors and return a 500 error.
        print(f"An unexpected error occurred: {e}")
        response.status = 500
        return "Internal Server Error"


@app.route('/')
def home():
    """
    Handles the home route and calls render_response_from_env.

    Returns:
        The response from render_response_from_env.
    """
    return render_response_from_env(app)


if __name__ == '__main__':
    # Example usage:  Run the Bottle application.
    #  Important:  In a production environment, use a production-ready WSGI server
    #  like Gunicorn or uWSGI.  Do *not* use the built-in development server.
    #  Also, configure HTTPS properly.

    #  This example is for local testing only.
    app.run(host='localhost', port=8080, debug=True, reloader=True)

