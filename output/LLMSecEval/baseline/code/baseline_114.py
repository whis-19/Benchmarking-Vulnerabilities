import os
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, Template
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.utils import secure_filename
import html

# Initialize Jinja2 environment (ideally, do this once at application startup)
template_dir = os.path.join(os.path.dirname(__file__), 'templates')  # Ensure 'templates' directory exists
env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)  # Enable autoescaping for security


def render_response_from_env(env: Environment, request: Request) -> Response:
    """
    Renders a template with a name parameter from the request and returns a Response.

    Args:
        env: The Jinja2 environment.
        request: The Werkzeug Request object.

    Returns:
        A Werkzeug Response object with the rendered template.
    """
    name = request.args.get('name', 'World')  # Default to 'World' if no name is provided

    # Sanitize the name input to prevent XSS attacks.  Crucially important.
    safe_name = html.escape(name)

    try:
        template: Template = env.get_template('hello.html')  # Replace 'hello.html' with your template name
    except Exception as e:
        # Handle template loading errors gracefully.  Log the error.
        print(f"Error loading template: {e}")  # Log the error (replace with proper logging)
        return Response("Error loading template.", status=500)

    try:
        rendered_template = template.render(name=safe_name)
    except Exception as e:
        # Handle template rendering errors gracefully. Log the error.
        print(f"Error rendering template: {e}")  # Log the error (replace with proper logging)
        return Response("Error rendering template.", status=500)

    return Response(rendered_template, mimetype='text/html')


def home(request: Request) -> Response:
    """
    Handles the home route and calls render_response_from_env.

    Args:
        request: The Werkzeug Request object.

    Returns:
        A Werkzeug Response object.
    """
    return render_response_from_env(env, request)


# Example usage with Werkzeug (minimal example)
def application(environ: Dict[str, Any], start_response) -> Any:
    """
    WSGI application entry point.
    """
    request = Request(environ)
    try:
        response = home(request)  # Call the home function with the request
    except HTTPException as e:
        response = e.get_response(request.environ)
    return response(environ, start_response)


if __name__ == '__main__':
    from werkzeug.serving import run_simple

    # Create a dummy 'templates' directory and 'hello.html' file for testing
    if not os.path.exists('templates'):
        os.makedirs('templates')
    with open('templates/hello.html', 'w') as f:
        f.write("<h1>Hello, {{ name }}!</h1>")

    run_simple('localhost', 5000, application)

