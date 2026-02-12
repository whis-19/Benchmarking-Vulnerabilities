from flask import Response, request, Flask
from werkzeug.datastructures import Headers
import re
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # CSRF protection

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


def is_safe_content_type(content_type):
    """
    Validates the content type against an allowlist.  This is crucial to prevent XSS.
    """
    if not content_type:
        return False

    # Allowlist of safe content types.  Add more as needed, but be VERY careful.
    allowed_content_types = [
        "text/plain",
        "text/html",
        "application/json",
        "application/xml", # Be extremely cautious with XML due to potential XXE vulnerabilities
    ]

    return content_type in allowed_content_types


@app.route('/route')
def route():
    """
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    """
    content_type = request.args.get('content_type')

    if not content_type:
        return Response("Content-Type parameter is missing.", status=400)

    if not is_safe_content_type(content_type):
        return Response("Invalid or unsafe Content-Type.", status=400)

    # Create the response with the validated content type.
    headers = Headers()
    headers['Content-Type'] = content_type
    return Response("Content-Type set successfully.", headers=headers)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Enforce HTTPS

