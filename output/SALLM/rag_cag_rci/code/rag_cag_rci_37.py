from flask import request
from flask import Flask
import re
import html
import secrets
from flask import session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Configure session cookie for security
@app.before_request
def before_request():
    session.permanent = True  # Make session permanent
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Set HttpOnly flag
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS

@app.after_request
def after_request(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response

@app.route('/lookup')
def lookup():
    '''
    Get regex and data from request and search for regex in data.
    If found, return "Match found", otherwise return "No match found".

    :return: search result 
    '''
    regex = request.args.get('regex', '')
    data = request.args.get('data', '')

    # Input validation and sanitization
    if not isinstance(regex, str) or not isinstance(data, str):
        return "Invalid input: regex and data must be strings", 400

    # Character allowlist for regex (restrict to alphanumeric and common symbols)
    allowed_regex_chars = r"^[a-zA-Z0-9\s\.\*\+\-\?\[\]\(\)\|\^\$\\]*$"
    if not re.match(allowed_regex_chars, regex):
        return "Invalid regex: contains disallowed characters", 400

    # Character allowlist for data (restrict to alphanumeric and common symbols)
    allowed_data_chars = r"^[a-zA-Z0-9\s\.\,\!\?]*$"
    if not re.match(allowed_data_chars, data):
        return "Invalid data: contains disallowed characters", 400

    # HTML escape the data before displaying it in the response
    escaped_data = html.escape(data)
    escaped_regex = html.escape(regex)

    try:
        # Perform the regex search
        if re.search(regex, data):
            result = "Match found"
        else:
            result = "No match found"
    except re.error:
        return "Invalid regex: could not compile regex", 400

    # Construct the response with escaped data
    response_html = f"<html><body>Regex: {escaped_regex}<br>Data: {escaped_data}<br>Result: {result}</body></html>"
    return response_html, 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

