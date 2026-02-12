import os
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.utils import secure_filename
import html

# Initialize Jinja2 environment (configure as needed)
template_dir = os.path.join(os.path.dirname(__file__), 'templates')  # Ensure 'templates' directory exists
env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)  # Autoescape for security

def render_response_from_env(env: Environment, request: Request) -> Response:
    """
    Renders a template based on the 'name' parameter from the request, using the provided Jinja2 environment.

    Args:
        env: The Jinja2 environment.
        request: The Werkzeug Request object.

    Returns:
        A Werkzeug Response object containing the rendered template.

    Raises:
        werkzeug.exceptions.NotFound: If the template is not found.
        werkzeug.exceptions.HTTPException: For other HTTP-related errors.
        Exception: For any other unexpected errors during rendering.
    """
    try:
        name = request.args.get("name", "World")  # Default to "World" if no name is provided

        # Sanitize the name parameter to prevent XSS.  Crucial!
        name = html.escape(name)

        template = env.get_template("hello.html")  # Replace "hello.html" with your template name

        # Render the template with the sanitized name
        rendered_template = template.render(name=name)

        # Create a Response object with the rendered template
        response = Response(rendered_template, mimetype="text/html")
        return response

    except TemplateNotFound:
        raise NotFound("Template not found")  # Raise a 404 error if the template doesn't exist
    except HTTPException as e:
        # Re-raise HTTP exceptions to be handled by the application
        raise e
    except Exception as e:
        # Log the error for debugging purposes (important in production)
        print(f"Error rendering template: {e}")
        # Return a generic error response (avoid exposing sensitive details)
        return Response("An error occurred while rendering the page.", status=500)


def home(request: Request) -> Response:
    """
    Handles the home route and calls render_response_from_env to generate the response.

    Args:
        request: The Werkzeug Request object.

    Returns:
        A Werkzeug Response object.
    """
    return render_response_from_env(env, request)


# Example usage (using Werkzeug's built-in server for demonstration)
if __name__ == '__main__':
    from werkzeug.serving import run_simple

    def application(environ: Dict[str, Any], start_response):
        request = Request(environ)
        try:
            if request.path == '/':
                response = home(request)
            else:
                raise NotFound()  # Handle other routes with a 404
        except HTTPException as e:
            response = e.get_response(environ)
        except Exception as e:
            # Generic error handling for unhandled exceptions
            print(f"Unhandled exception: {e}")
            response = Response("Internal Server Error", status=500)

        return response(environ, start_response)

    # Create a 'templates' directory and a 'hello.html' file for testing
    if not os.path.exists("templates"):
        os.makedirs("templates")
    if not os.path.exists("templates/hello.html"):
        with open("templates/hello.html", "w") as f:
            f.write("<h1>Hello, {{ name }}!</h1>")

    run_simple('localhost', 5000, application)

