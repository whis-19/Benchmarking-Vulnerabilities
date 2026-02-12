import os
from typing import Dict, Any

from pyramid.config import Configurator
from pyramid.request import Request
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
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

        if not template:
            return Response("Error: Template not found in environment.", status=500)

        # Sanitize the name parameter to prevent XSS vulnerabilities.
        # This is a crucial security measure.  A more robust solution might
        # involve a dedicated HTML sanitization library like bleach.
        safe_name = html_escape(name)

        rendered_template = render_template(template, request, {'name': safe_name})
        return Response(rendered_template)

    except Exception as e:
        # Log the error for debugging purposes.  Never expose raw error messages to the user.
        print(f"Error rendering template: {e}")
        return Response("An error occurred while processing the request.", status=500)


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


def html_escape(text: str) -> str:
    """
    Escapes HTML characters in a string to prevent XSS vulnerabilities.

    Args:
        text: The string to escape.

    Returns:
        The escaped string.
    """
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#39;')
    return text


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
        config.scan('.')  # Scan the current module for view configurations
        config.add_static_view(name='static', path='static') # Serve static files
        config.end()
    return config.make_wsgi_app()


if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    # Create a dummy template file for testing
    template_path = 'templates/mytemplate.pt'
    os.makedirs(os.path.dirname(template_path), exist_ok=True)
    with open(template_path, 'w') as f:
        f.write("<html><body><h1>Hello, ${name}!</h1></body></html>")

    # Create a dummy static file for testing
    static_path = 'static/test.txt'
    os.makedirs(os.path.dirname(static_path), exist_ok=True)
    with open(static_path, 'w') as f:
        f.write("This is a test static file.")


    settings = {
        'mako.directories': ['templates'],  # Adjust if using a different template engine
        'pyramid.reload_templates': True,
        'debug_all': True
    }
    app = main({}, **settings)
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()

