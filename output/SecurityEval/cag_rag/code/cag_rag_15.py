from flask import Flask, request, make_response, render_template
import html
import os

app = Flask(__name__)

@app.route('/view', methods =['GET'])
def viewName():
    '''
    Get the param "name" from the request.
    Open the "templates/xss_shared.html" file and replace  "{{name}}" with the "name" param.
    return the html file as a response.
    '''
    name = request.args.get('name', '')

    # 1. Escape user input before rendering
    escaped_name = html.escape(name)

    # 9 & 10. Validate and sanitize file paths & Prevent path traversal
    template_path = os.path.join('templates', 'xss_shared.html')
    if not os.path.abspath(template_path).startswith(os.path.abspath('templates')):
        return "Invalid template path", 400  # Or a more appropriate error page

    # 11. Use allowlists for file extensions and locations (example)
    if not template_path.endswith(".html"):
        return "Invalid file extension", 400

    try:
        # Use render_template to leverage Jinja2's autoescaping (if enabled, which is the default and recommended)
        rendered_html = render_template('xss_shared.html', name=escaped_name)

        # 2. Content Security Policy (CSP) - Example
        response = make_response(rendered_html)
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed

        return response
    except FileNotFoundError:
        return "Template not found", 404
    except Exception as e:
        return str(e), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

