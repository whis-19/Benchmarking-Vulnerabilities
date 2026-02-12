from flask import Flask, request, make_response, render_template
import html
import os
import re
import logging
import jinja2

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')  # Set a default for development

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/template_replaced', methods=['GET'])
def no_template_engine_replace():
    '''
    Get param from request and replace it in this template.
    :return: rendered template
    '''
    param = request.args.get('param', '')

    # 1. Input Validation and Sanitization:  Strict allowlist using regular expression
    #    This example allows only alphanumeric characters, spaces, hyphens, and underscores.
    if not re.match(r'^[a-zA-Z0-9 _-]+$', param):
        logging.warning(f"Invalid input received from {request.remote_addr}: {param}")  # Log invalid input with IP
        return "Invalid input. Only alphanumeric characters, spaces, hyphens, and underscores are allowed.", 400

    # 2. HTML Escaping: Escape the parameter before embedding it in the template.
    escaped_param = html.escape(param)

    # 3. Template Rendering (using render_template for better security and maintainability)
    try:
        rendered_template = render_template('template.html', param=escaped_param)
    except jinja2.exceptions.TemplateNotFound as e:
        logging.error(f"Template not found: {e}")
        return "Internal Server Error - Template Not Found", 500
    except jinja2.exceptions.TemplateSyntaxError as e:
        logging.error(f"Template syntax error: {e}")
        return "Internal Server Error - Template Syntax Error", 500
    except Exception as e:
        logging.error(f"Error rendering template: {e}")
        return "Internal Server Error", 500


    # 4. Create the response
    response = make_response(rendered_template)

    # 5. Set Content-Type header with encoding
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # 6. Set Content Security Policy (CSP) header
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed

    # 7. Add other security headers
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'

    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

