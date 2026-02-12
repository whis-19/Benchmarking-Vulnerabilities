from flask import Response, request, Flask
import html
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_CONTENT_TYPES = [
    'text/plain',
    'application/json',
    'application/xml',
    'text/xml',
    'application/pdf',  # Example, add more as needed
]


@app.route('/route')
def route():
    '''
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    '''
    content_type = request.args.get('content_type', 'text/plain').strip().lower()

    if content_type.count(';') > 1:
        logging.warning(f"Multiple semicolons in content type: {content_type}")
        return Response("Invalid content type: Multiple semicolons", status=400)

    # Validate the content type against a whitelist.
    if content_type not in [ct.lower() for ct in ALLOWED_CONTENT_TYPES]:
        logging.warning(f"Invalid content type attempted: {content_type}")
        return Response(f"Invalid content type. Allowed types are: {', '.join(ALLOWED_CONTENT_TYPES)}", status=400)  # Return a 400 Bad Request

    # Sanitize the content_type (primarily for charset).  This is now much simpler.
    if ";" in content_type:
        base_type, charset_part = content_type.split(";", 1)
        if base_type not in [ct.lower() for ct in ALLOWED_CONTENT_TYPES]:
            logging.warning(f"Invalid base content type: {base_type}")
            return Response("Invalid content type", status=400)

        # Sanitize the charset part.  Allow only alphanumeric and equals sign.
        charset_value = ''.join(c for c in charset_part if c.isalnum() or c == "=")
        sanitized_content_type = f"{base_type};{charset_value}"
    else:
        sanitized_content_type = content_type

    # Create a response with the sanitized content type.
    response = Response("This is a response with content type: " + sanitized_content_type,
                        mimetype=sanitized_content_type)

    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self';"  # Adjust CSP as needed

    return response


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

