import os
from typing import Dict
import re
import logging

from jinja2 import Environment, FileSystemLoader, Template
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.ERROR, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')


def render_response_from_env(env: Environment, request: Request) -> Response:
    """
    Renders a template based on the 'name' parameter from the request,
    using the provided Jinja2 environment.  Handles potential errors
    securely.

    Args:
        env: The Jinja2 environment configured with template paths.
        request: The Werkzeug request object.

    Returns:
        A Werkzeug Response object containing the rendered template.
    """
    try:
        name = request.args.get("name", "World")  # Default to "World" if no name is provided

        # Sanitize the name parameter to prevent template injection.
        # Use a regular expression to allow only alphanumeric characters and spaces.
        safe_name = re.sub(r"[^a-zA-Z0-9 ]", "", name)

        # Load the template.  Hardcoding the template name is generally safer
        # than allowing the user to specify it, which could lead to template
        # injection vulnerabilities.
        template: Template = env.get_template("hello.html")

        # Render the template with the sanitized name.
        rendered_template = template.render(name=safe_name)

        response = Response(rendered_template, mimetype="text/html")
        return response

    except Exception as e:
        # Log the error for debugging purposes.  Never expose raw error messages
        # to the user in a production environment.
        logging.error(f"Error rendering template: {e}", exc_info=True)

        # Return a generic error response to the user.  This prevents information
        # leakage about the server's internal state.
        return Response("An error occurred while processing your request.", status=500)


def home(env: Environment, request: Request) -> Response:
    """
    Handles the home route, calling render_response_from_env to generate the response.

    Args:
        env: The Jinja2 environment.
        request: The Werkzeug request object.

    Returns:
        A Werkzeug Response object.
    """
    return render_response_from_env(env, request)


def create_app(template_dir: str) -> Dict:
    """
    Creates the Jinja2 environment and returns a dictionary of routes.

    Args:
        template_dir: The directory containing the templates.

    Returns:
        A dictionary mapping routes to handler functions.
    """
    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        return {"/": home}
    except Exception as e:
        logging.error(f"Error creating app: {e}", exc_info=True)
        # Return a default set of routes or raise an exception
        return {}


def application(environ: Dict, start_response):
    """
    WSGI application entry point.

    Args:
        environ: The WSGI environment dictionary.
        start_response: The WSGI start_response callable.

    Returns:
        An iterable of bytes representing the response body.
    """
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    routes = create_app(template_dir)

    request = Request(environ)

    try:
        # Get the handler function for the requested path.
        handler = routes.get(request.path)
        if handler is None:
            raise NotFound()

        # Call the handler function to generate the response.
        response = handler(Environment(loader=FileSystemLoader(template_dir)), request)

    except HTTPException as e:
        # Handle HTTP exceptions (e.g., 404 Not Found).
        response = e.get_response(request.environ)

    # Add security headers
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP - adjust as needed
    response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"
    # IMPORTANT: Remember to submit your site to the HSTS preload list (e.g., via hstspreload.org)

    # Send the response headers and body.
    return response(environ, start_response)


if __name__ == "__main__":
    from werkzeug.serving import run_simple

    # Create a dummy template directory and a hello.html template.
    template_dir = "templates"
    os.makedirs(template_dir, exist_ok=True)
    with open(os.path.join(template_dir, "hello.html"), "w") as f:
        f.write("<h1>Hello, {{ name }}!</h1>")

    # Run the application in development mode.
    run_simple("localhost", 5000, application)

