from flask import Flask, request, make_response, render_template_string
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import os

app = Flask(__name__)

# Configure Jinja2 environment
#  - Autoescape is crucial to prevent XSS
#  - StrictUndefined raises an error if a variable is not defined, helping catch errors
#  - Enable caching for performance (optional, but recommended)
app.jinja_env.autoescape = True
app.jinja_env.undefined = StrictUndefined
app.jinja_env.cache = {}  # Or use a more robust caching mechanism

#  Use a safe path for templates.  Avoid relative paths that could lead to directory traversal.
template_dir = os.path.join(app.root_path, 'templates')
loader = FileSystemLoader(searchpath=template_dir)
app.jinja_env.loader = loader


@app.route('/')
def render_template():
    '''
    Get name from the request using 'name'.
    Render the template with the name from the jinja2 template.
    :return: The rendered template.
    '''
    name = request.args.get('name', 'World')  # Provide a default value

    # Sanitize the input.  This is critical to prevent XSS.
    #  This example uses a simple whitelist approach.  Consider using a more robust library like bleach.
    #  NEVER directly render unsanitized user input.
    safe_name = ''.join(c for c in name if c.isalnum() or c in ' ')  # Allow alphanumeric and spaces

    try:
        # Render the template with the sanitized name
        rendered_template = render_template_string(open(os.path.join(template_dir, 'hello.html')).read(), name=safe_name)
        return rendered_template
    except Exception as e:
        # Handle template rendering errors gracefully.  Don't expose sensitive information in the error message.
        print(f"Template rendering error: {e}")  # Log the error for debugging
        return "An error occurred while rendering the template.", 500


if __name__ == '__main__':
    #  NEVER run in production with debug=True.  It exposes sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

