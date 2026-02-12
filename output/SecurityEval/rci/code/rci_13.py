from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/render')
def render_response_from_env():
    '''
    Get the argument "name" from request, and render a template string.
    '''
    name = request.args.get('name', 'World')  # Provide a default value

    # Sanitize the name input to prevent XSS
    name = escape(name)

    # **CRITICAL SECURITY FIX:  Do NOT load templates from user-controlled paths.**
    # **NEVER use request.args.get() to specify the template path.**
    # **This is a major vulnerability that allows attackers to read arbitrary files on the server (Server-Side Template Injection - SSTI).**

    # **Instead, use a fixed, safe template string.**
    template_string = "<h1>Hello, {{ name }}!</h1>"
    rendered_html = render_template_string(template_string, name=name)
    return rendered_html

if __name__ == '__main__':
    app.run(debug=False) # NEVER RUN IN DEBUG MODE IN PRODUCTION

