import os
from typing import Dict, Any

from pyramid.config import Configurator
from pyramid.request import Request
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render_template
import bleach
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define allowed templates and their corresponding file paths.  This is the whitelist.
ALLOWED_TEMPLATES = {
    'home': 'templates/home.pt',
    # Add other allowed templates here
}


def render_response_from_env(env: Dict[str, Any], request: Request) -> Response:
    """
    Renders a template with a name parameter obtained from the request.  Prevents template injection.

    Args:
        env: A dictionary containing the environment, including the template name.
        request: The Pyramid request object.

    Returns:
        A Pyramid Response object containing the rendered template.
    """
    try:
        name = request.params.get('name', 'World')

        if len(name) > 100:
            logger.warning(f"Name input too long: {name}")
            return Response("Error: Name is too long.", status=400)

        template_name = env.get('template_name')

        if not template_name or template_name not in ALLOWED_TEMPLATES:
            logger.error(f"Invalid template name: {template_name}")
            return Response("Error: Invalid template.", status=500)

        template_path = ALLOWED_TEMPLATES[template_name]

        safe_name = bleach.clean(name, tags=[], attributes={}, styles=[])

        rendered_template = render_template(template_path, request, {'name': safe_name})
        return Response(rendered_template)

    except Exception as e:
        error_id = os.urandom(16).hex()  # Generate a unique error ID
        logger.exception(f"Error rendering template (Error ID: {error_id}):")
        return Response(f"An error occurred while processing the request. Error ID: {error_id}", status=500)


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
        'template_name': 'home'  # Use the *name* from ALLOWED_TEMPLATES
    }
    return render_response_from_env(env, request)


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
        config.include('pyramid_jinja2')
        config.add_route('home', '/')
        config.scan('.')
        config.add_static_view(name='static', path='static')
    return config.make_wsgi_app()


if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    # Create a dummy template file for testing
    template_path = 'templates/home.pt'  # Use the name from ALLOWED_TEMPLATES
    os.makedirs(os.path.dirname(template_path), exist_ok=True)
    with open(template_path, 'w') as f:
        f.write("<html><body><h1>Hello, ${name}!</h1></body></html>")

    # Create a dummy static file for testing
    static_path = 'static/test.txt'
    os.makedirs(os.path.dirname(static_path), exist_ok=True)
    with open(static_path, 'w') as f:
        f.write("This is a test static file.")

    settings = {
        'mako.directories': ['templates'],
        'pyramid.reload_templates': True,
        #'debug_all': True  # NEVER ENABLE IN PRODUCTION
    }
    app = main({}, **settings)
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()

