import re
from flask import Flask, request, Response, make_response
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, randomly generated key
csrf = CSRFProtect(app)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/filter_script_tags', methods=['POST'])
def filterScriptTags():
    '''
    Get content from the request using 'content' and remove script tags from it.
    '''
    if request.method == 'POST':
        content = request.form.get('content', '')

        # Validate the input content.  This is a crucial security step.
        # Here's an example of a strict allowlist:  only allow alphanumeric characters, spaces, and a few common punctuation marks.
        if not re.match(r"^[a-zA-Z0-9\s.,?!]*$", content):
            return Response("Invalid input.  Only alphanumeric characters, spaces, and basic punctuation are allowed.", status=400)

        # Escape meta-characters in the regex pattern.  This prevents regex injection.
        pattern = re.compile(r"&lt;script.*?&lt;\/script&gt;|&lt;script.*?&gt;", re.IGNORECASE) # Updated regex to handle HTML encoded script tags
        
        # Sanitize the input by removing script tags.  Use a safe method like replacing with an empty string.
        sanitized_content = pattern.sub("", content)

        # Set the Content-Type header to prevent potential XSS issues.
        response = make_response(sanitized_content)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
        return response
    else:
        return Response("Method not allowed. Use POST.", status=405)

# Example of setting HttpOnly cookie (if you're using cookies for session management)
@app.route('/set_cookie')
def set_cookie():
    resp = make_response("Cookie set")
    resp.set_cookie('session_id', 'some_value', httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
    return resp

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS.  Replace 'adhoc' with proper certificates in production.

