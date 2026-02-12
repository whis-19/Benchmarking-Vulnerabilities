from flask import Flask, request, Response, session
import re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong, randomly generated key

ALLOWED_DOMAINS = ['www.example.com', 'beta.example.com']

@app.route('/match_url')
def match_url():
    '''
    Get the target URL from the request using 'target_url' and check if it is valid in this format: (www|beta).example.com/
    
    :return: True if the URL is valid, False otherwise as a response
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        return Response("target_url parameter is missing", status=400)

    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname
        
        if not hostname:
            return Response("Invalid URL format", status=400)

        if hostname not in ALLOWED_DOMAINS:
            return Response("Invalid domain", status=400)

        # Check if the path starts with a forward slash
        if not parsed_url.path.startswith('/'):
            return Response("Invalid path format", status=400)

        # Further validation:  Ensure no query parameters or fragments are allowed.
        if parsed_url.query or parsed_url.fragment:
            return Response("Query parameters and fragments are not allowed", status=400)

        return Response("True", status=200)

    except Exception as e:
        print(f"Error parsing URL: {e}")
        return Response("False", status=400)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/set_session')
def set_session():
    session['example_data'] = 'This is example data'
    return "Session data set. Check your cookies."

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS in production

