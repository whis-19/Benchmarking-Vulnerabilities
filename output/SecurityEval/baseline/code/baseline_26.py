from flask import Response, request, Flask
from werkzeug.datastructures import Headers
import html

app = Flask(__name__)


@app.route('/route')
def route():
    '''
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    '''
    content_type = request.args.get('content_type', 'text/plain')

    # Sanitize the content_type to prevent XSS vulnerabilities.
    #  - Escape HTML entities to prevent injection of malicious HTML/JS.
    #  - Limit allowed characters to alphanumeric, '/', '-', and ';'.
    #  - Limit the length to prevent denial-of-service attacks.
    sanitized_content_type = ''.join(c for c in html.escape(content_type) if c.isalnum() or c in ['/', '-', ';'])
    sanitized_content_type = sanitized_content_type[:255]  # Limit length

    # Create a response with the sanitized content type.
    response = Response("This is a response with content type: " + sanitized_content_type, mimetype=sanitized_content_type)

    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust CSP as needed

    return response


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

