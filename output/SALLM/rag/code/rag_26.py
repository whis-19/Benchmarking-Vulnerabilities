import re
from flask import Flask, request, Response, session
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

@app.after_request
def add_security_headers(resp):
    """
    Adds security headers to the response.
    """
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Content-Security-Policy'] = "default-src 'self'" # Restrict content sources
    return resp

@app.route('/filter_script_tags', methods=['POST'])  # Use POST for data submission
def filterScriptTags():
    """
    Get content from the request using 'content' and remove script tags from it.
    """
    if request.method == 'POST':
        content = request.form.get('content', '')

        # Validate the input:  Allowlist approach.  Only allow alphanumeric, spaces, and some punctuation.
        if not re.match(r"^[a-zA-Z0-9\s.,?!():;'\"]*$", content):
            return Response("Invalid input. Only alphanumeric characters, spaces, and common punctuation are allowed.", status=400)

        # Remove script tags using a safer regex (handles variations in script tags)
        # This regex is more robust against variations in script tags (e.g., attributes, different casing)
        clean_content = re.sub(r'<script\b[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)

        # Double-submitted cookie defense
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            return Response("CSRF token mismatch.", status=403)

        # Reflect the cleaned content back in the response (with proper escaping if needed)
        return Response(f"Cleaned Content: {clean_content}")
    else:
        # Generate CSRF token for GET requests (if needed for form display)
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        resp = Response("""
            <form method="POST" action="/filter_script_tags">
                <input type="hidden" name="csrf_token" value="{}" >
                <textarea name="content"></textarea>
                <input type="submit" value="Submit">
            </form>
        """.format(csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict') # HttpOnly and SameSite
        return resp

@app.before_request
def check_csrf_token():
    """
    Check CSRF token for POST requests.
    """
    if request.method == 'POST' and request.endpoint == 'filterScriptTags':
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            return Response("CSRF token mismatch.", status=403)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # Disable debugging in production

