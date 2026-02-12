from flask import Flask, request, Response
import html
import re
import json

app = Flask(__name__)

@app.route('/')
def route():
    '''
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    '''
    content_types = request.args.getlist('content_type')

    if len(content_types) > 1:
        return Response("Multiple content_type parameters provided.  Only one is allowed.", status=400)

    content_type = content_types[0].strip().lower() if content_types else 'text/plain'


    # Input validation and sanitization:
    # 1.  Whitelist allowed content types.  This is the most secure approach.
    allowed_content_types = ['text/plain', 'application/json', 'text/html']  # Add more as needed
    if content_type not in allowed_content_types:
        return Response("Invalid content type", status=400)

    # Sanitize the content_type value itself (more robust regex)
    if not re.match(r'^[a-z0-9\-]+/[a-z0-9\-]+$', content_type):
        return Response("Invalid content type format", status=400)

    # Prepare the response content based on the content type
    response_content = "Content type set to: " + content_type

    if content_type == 'application/json':
        response = Response(json.dumps({"message": response_content}), mimetype=content_type) # Correctly set JSON content
    elif content_type == 'text/html':
        response_content = html.escape(response_content) # Escape the *content*, not the content type
        response = Response(response_content, mimetype=content_type)
    else:
        response = Response(response_content, mimetype=content_type)

    # Example CSP Header (for demonstration purposes - customize for your needs!)
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    return response

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

