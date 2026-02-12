import os
from flask import Flask, request, render_template_string, make_response, session
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# Initialize Jinja2 environment with autoescape enabled
template_env = Environment(
    loader=FileSystemLoader('.'),  # Or specify your template directory
    autoescape=select_autoescape(['html', 'xml'])
)

def render_response_from_env(env):
    """
    Renders a template with a name parameter from the request, ensuring security.
    """
    name = request.args.get('name', '')

    # Input Validation:  Strict allowlist for the 'name' parameter.
    #  This example allows only alphanumeric characters and spaces.
    if not all(c.isalnum() or c.isspace() for c in name):
        name = "Invalid Input"  # Or handle the error more gracefully, e.g., display an error page

    template = env.get_template('template.html')  # Replace 'template.html' with your actual template file

    # Context:  Pass the validated name to the template.
    rendered_template = template.render(name=name)

    response = make_response(rendered_template)

    # Security Headers:  Set Content-Type and HttpOnly cookie.
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    session.permanent = True  # Make the session permanent
    response.set_cookie('sessionid', session.sid, httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes

    return response


@app.route('/')
def home():
    """
    Handles the home route and calls render_response_from_env.
    """
    return render_response_from_env(template_env)


if __name__ == '__main__':
    # IMPORTANT:  Disable debugging in production!
    app.run(debug=False, host='0.0.0.0', port=5000)


# Example template.html (place in the same directory as the Python script):
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <title>Greeting</title>
# </head>
# <body>
#     <h1>Hello, {{ name }}!</h1>
# </body>
# </html>

