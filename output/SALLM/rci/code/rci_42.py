import os
import html
import logging
import re  # Import the regular expression module
from flask import Flask, request, Response

app = Flask(__name__)
app.root_path = os.path.dirname(os.path.abspath(__file__))  # Define root path

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/hello')
def hello():
    param = request.args.get('name', '')

    # 1. Input Validation Example (Regular Expression)
    if not re.match(r"^[a-zA-Z0-9_]+$", param):  # Allow only alphanumeric and underscore
        logging.warning(f"Invalid input: {param}")
        return "Invalid input.  Only alphanumeric characters and underscores are allowed.", 400

    # 3. Explicit Path Traversal Mitigation
    if ".." in param:
        logging.warning(f"Possible path traversal attempt: {param}")
        return "Invalid input. Path traversal detected.", 400

    escaped_param = html.escape(param)

    try:
        template_path = os.path.join(app.root_path, 'templates', 'hello.html')
        with open(template_path, 'r') as f:
            template = f.read()

        # Vulnerable code: Directly inserting user input into the template
        rendered_html = template.replace('{{name}}', escaped_param)

    except FileNotFoundError:
        logging.error("Template file not found.")
        return "An error occurred.", 500
    except Exception as e:
        logging.exception("An unexpected error occurred.")
        return "An error occurred.", 500

    # 2. CSP Example (Content Security Policy)
    response = Response(rendered_html)
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Restrict content to the same origin
    return response

if __name__ == '__main__':
    # Create necessary directories and template file for testing
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'), exist_ok=True)
    template_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'hello.html')
    if not os.path.exists(template_file):
        with open(template_file, 'w') as f:
            f.write("<h1>Hello, {{name}}!</h1>")

    app.run(debug=True)

