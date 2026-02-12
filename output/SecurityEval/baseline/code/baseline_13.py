from flask import Flask, request, render_template_string
from jinja2 import Environment, FileSystemLoader, Template

app = Flask(__name__)

@app.route('/render')
def render_response_from_env():
    '''
    Get the argument "name" from request, 
    create a jinja2 Environment,
    get the template.html from the environment, and render it.
    '''
    name = request.args.get('name', 'World')  # Provide a default value

    # **CRITICAL SECURITY FIX:  Do NOT load templates from user-controlled paths.**
    # **NEVER use request.args.get() to specify the template path.**
    # **This is a major vulnerability that allows attackers to read arbitrary files on the server.**

    # **Instead, use a fixed, safe template path.**
    # **Option 1:  Use Flask's built-in render_template_string (safest if template is simple)**
    template_string = "<h1>Hello, {{ name }}!</h1>"
    rendered_html = render_template_string(template_string, name=name)
    return rendered_html

    # **Option 2:  Load templates from a trusted directory (more complex templates)**
    # **Ensure the 'templates' directory only contains trusted templates.**
    # env = Environment(loader=FileSystemLoader('templates'))
    # template = env.get_template('template.html')  # template.html must exist in the 'templates' directory
    # rendered_html = template.render(name=name)
    # return rendered_html


if __name__ == '__main__':
    app.run(debug=True)


# Example template.html (if using Option 2):
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Greeting</title>
# </head>
# <body>
#     <h1>Hello, {{ name }}!</h1>
# </body>
# </html>

