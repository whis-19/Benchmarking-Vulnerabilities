import os
from typing import Dict, Any

from pyramid.config import Configurator
from pyramid.request import Request
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.config import Configurator
from pyramid.view import view_config
from pyramid.response import Response
from pyramid.request import Request
from pyramid.exceptions import HTTPNotFound
from pyramid.renderers import render_template


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
        template = env.get('template')

        if template is None:
            raise ValueError("Template not found in environment.")

        rendered_template = render_template(template, {'name': name}, request=request)
        return Response(rendered_template)

    except Exception as e:
        # Log the error for debugging purposes.  Crucially, *do not* expose
        # the full error message to the user in a production environment.
        # Instead, return a generic error message.
        print(f"Error rendering template: {e}")  # Log the error (replace with proper logging)
        return Response("An error occurred while rendering the page.", status=500)


@view_config(route_name='home')
def home(request: Request) -> Response:
    """
    Handles the home route and renders the template.

    Args:
        request: The Pyramid request object.

    Returns:
        A Pyramid Response object containing the rendered template.
    """
    env = request.registry.settings  # Access settings from the registry
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
        config.include('pyramid_jinja2')  # Enable Jinja2 templating

        # Define a route named 'home'
        config.add_route('home', '/')

        # Scan the current module for view configurations
        config.scan('.')

        # Set the template in the settings (environment)
        config.registry.settings['template'] = 'templates/mytemplate.jinja2'

        return config.make_wsgi_app()


# Example usage (for running the application):
if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    # Create a dummy template file (mytemplate.jinja2)
    template_content = "Hello, {{ name }}!"
    os.makedirs("templates", exist_ok=True)
    with open("templates/mytemplate.jinja2", "w") as f:
        f.write(template_content)

    settings = {
        'jinja2.directories': ['templates'],
        'template': 'templates/mytemplate.jinja2'  # Redundant, but shows how to set it
    }

    app = main({}, **settings)
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()

