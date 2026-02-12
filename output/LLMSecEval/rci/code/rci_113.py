import os
from typing import Dict, Any

from pyramid.config import Configurator
from pyramid.request import Request
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render_template
import bleach  # Import bleach
import logging
from pyramid.events import NewResponse
from pyramid.csrf import new_csrf_token, check_csrf_token
from pyramid.exceptions import BadCSRFToken
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def add_csp_header(event):
    """
    Adds a Content Security Policy (CSP) header to the response.

    This helps mitigate XSS attacks by controlling the sources from which the browser
    is allowed to load resources.  Adjust the CSP based on your application's needs.
    """
    event.response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"


def render_response_from_env(env: Dict[str, Any], request: Request) -> Response:
    """
    Renders a template with a name parameter obtained from the request.

    Args:
        env: A dictionary containing the environment, including the template.
        request: The Pyramid request object.

    Returns:
        A Pyramid Response object containing the rendered template.
    """
    try:
        name = request.params.get('name', 'World')  # Default to 'World' if name is not provided

        # Input validation (example - limit length)
        if len(name) > 100:
            logger.warning(f"Name exceeds maximum length: {name}")
            return Response("Error: Name is too long.", status=400)

        template = env.get('template')

        if not template:
            logger.error("Template not found in environment.")
            return Response("Error: Template not found in environment.", status=500)

        # Sanitize the name parameter to prevent XSS vulnerabilities using bleach.
        # Configure bleach to allow specific tags and attributes.
        allowed_tags = ['b', 'i', 'em', 'strong']
        allowed_attributes = {'a': ['href', 'rel']}
        safe_name = bleach.clean(name, tags=allowed_tags, attributes=allowed_attributes)  # Use bleach for robust sanitization

        rendered_template = render_template(template, request, {'name': safe_name})
        return Response(rendered_template)

    except Exception as e:
        # Log the error for debugging purposes.  Never expose raw error messages to the user.
        logger.exception("Error rendering template:")  # Log the full exception
        return Response("An error occurred while processing the request.", status=500)


def csrf_protected(view):
    """
    Decorator to enforce CSRF protection on a view.
    """
    @wraps(view)
    def wrapper(request):
        try:
            check_csrf_token(request)
        except BadCSRFToken:
            logger.warning("CSRF token validation failed.")
            return Response("CSRF token is invalid.", status=400)
        return view(request)
    return wrapper


@view_config(route_name='home')
def home(request: Request) -> Response:
    """
    Handles the home route and calls render_response_from_env to render the response.

    Args:
        request: The Pyramid request object.

    Returns:
        A Pyramid Response object.
    """
    env = {
        'template': 'templates/mytemplate.pt'  # Replace with your actual template path
    }
    return render_response_from_env(env, request)


@view_config(route_name='form', request_method='GET', renderer='templates/form.pt')
def form_view(request):
    """
    Renders a simple form with a CSRF token.
    """
    csrf_token = new_csrf_token(request)
    return {'csrf_token': csrf_token}


@view_config(route_name='form', request_method='POST')
@csrf_protected
def form_submit(request):
    """
    Handles the form submission, protected by CSRF.
    """
    try:
        # Process the form data here
        submitted_data = request.params.get('data', '')
        logger.info(f"Form submitted with data: {submitted_data}")
        return Response("Form submitted successfully!", status=200)
    except Exception as e:
        logger.exception("Error processing form submission:")
        return Response("An error occurred during form submission.", status=500)


def main(global_config: Dict[str, str], **settings: Dict[str, Any]) -> Configurator:
    """
    Configures the Pyramid application.

    Args:
        global_config: Global configuration settings.
        settings: Application-specific settings.

    Returns:
        A Pyramid Configurator object.
    """
    with Configurator(settings=settings) as config:
        config.include('pyramid_jinja2')  # Or pyramid_chameleon, depending on your template engine
        config.add_route('home', '/')
        config.add_route('form', '/form')  # Route for the form
        config.scan('.')  # Scan the current module for view configurations
        config.add_static_view(name='static', path='static') # Serve static files
        config.add_subscriber(add_csp_header, NewResponse) # Add the CSP header
        config.include('pyramid_csrf')  # Enable CSRF protection
        config.set_csrf_storage_policy(None) # Use default cookie storage
        config.end()
    return config.make_wsgi_app()


if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    # Create a dummy template file for testing
    template_path = 'templates/mytemplate.pt'
    os.makedirs(os.path.dirname(template_path), exist_ok=True)
    with open(template_path, 'w') as f:
        f.write("<html><body><h1>Hello, ${name}!</h1></body></html>")

    # Create a dummy form template
    form_template_path = 'templates/form.pt'
    os.makedirs(os.path.dirname(form_template_path), exist_ok=True)
    with open(form_template_path, 'w') as f:
        f.write("""
        <html>
        <body>
            <form action="/form" method="post">
                <input type="hidden" name="csrf_token" value="${csrf_token}">
                <label for="data">Enter some data:</label>
                <input type="text" id="data" name="data">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
        """)

    # Create a dummy static file for testing
    static_path = 'static/test.txt'
    os.makedirs(os.path.dirname(static_path), exist_ok=True)
    with open(static_path, 'w') as f:
        f.write("This is a test static file.")


    settings = {
        'mako.directories': ['templates'],  # Adjust if using a different template engine
        'pyramid.reload_templates': True,
        # 'debug_all': True  # NEVER ENABLE IN PRODUCTION
        'pyramid.csrf.cookie_name': 'my_csrf_token',  # Customize CSRF cookie name
        'pyramid.csrf.header_name': 'X-CSRF-Token',  # Customize CSRF header name
    }
    app = main({}, **settings)
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()

