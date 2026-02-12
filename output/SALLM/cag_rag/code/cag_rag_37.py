from flask import request
from flask import Flask
import re
import html

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 10

@app.after_request
def add_header(response):
    """
    Adds headers to the response for security.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Guideline 11
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
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

    # Input validation and sanitization (Guidelines 6, 8, 9)
    if not isinstance(regex, str) or not isinstance(data, str):
        return "Invalid input: regex and data must be strings", 400

    # Sanitize inputs to prevent XSS (Guideline 7)
    regex = html.escape(regex)
    data = html.escape(data)

    # Regex validation (Guideline 8) -  Restrict allowed characters.  This is crucial.
    #  This example allows only alphanumeric characters, spaces, and a few common symbols.
    #  Adjust the allowlist based on your specific needs.  Be very restrictive.
    allowed_regex_chars = r"^[a-zA-Z0-9\s\.\*\+\-\?\{\}\(\)\[\]\^\$\|\\]*$"
    if not re.match(allowed_regex_chars, regex):
        return "Invalid regex: Only alphanumeric characters, spaces, and . * + - ? { } ( ) [ ] ^ $ | \ are allowed.", 400


    try:
        # Perform the regex search
        if re.search(regex, data):
            result = "Match found"
        else:
            result = "No match found"
    except re.error:
        return "Invalid regex pattern", 400

    # Escape the result for safe output (Guideline 7)
    result = html.escape(result)

    return result

