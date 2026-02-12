from flask import Flask, request, Response
import html
import re

app = Flask(__name__)

@app.route('/')
def route():
    '''
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    '''
    content_type = request.args.get('content_type', 'text/plain')

    # Input validation and sanitization:
    # 1.  Whitelist allowed content types.  This is the most secure approach.
    allowed_content_types = ['text/plain', 'application/json', 'text/html']  # Add more as needed
    if content_type not in allowed_content_types:
        return Response("Invalid content type", status=400)

    # 2.  Alternatively, sanitize the input to prevent injection attacks.
    #    This is less secure than whitelisting, but may be necessary if
    #    the range of allowed content types is very large.
    #    Example:  Escape HTML entities if the content type is text/html.
    #    This prevents XSS if the content type is reflected in the response.
    if content_type == 'text/html':
        content_type = html.escape(content_type)

    # 3.  Regular expression to validate the content type format.
    #    This is a basic check and may not catch all vulnerabilities.
    if not re.match(r'^[a-z]+/[a-z]+$', content_type):
        return Response("Invalid content type format", status=400)


    response = Response("Content type set to: " + content_type, mimetype=content_type)
    return response

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

