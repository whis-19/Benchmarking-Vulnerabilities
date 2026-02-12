from flask import request
from flask import Flask
import re
import html
from urllib.parse import quote

app = Flask(__name__)

# Set the session cookie to HttpOnly (best done in app configuration, but included here for completeness)
app.config['SESSION_COOKIE_HTTPONLY'] = True

@app.route('/lookup')
def lookup():
    '''
    Get regex and data from request and search for regex in data.
    If found, return "Match found", otherwise return "No match found".

    :return: search result 
    '''
    regex = request.args.get('regex', '')
    data = request.args.get('data', '')

    # Validate inputs:  Strict allowlist and disallow metacharacters if possible.
    # This example allows only alphanumeric characters, spaces, and a few common symbols.
    # Adjust the allowlist based on your specific needs.  If you *need* metacharacters,
    # you'll need to escape them properly before using them in re.search.
    allowed_chars_regex = r"^[a-zA-Z0-9\s.,?!():;'\"]*$"
    allowed_chars_data = r"^[a-zA-Z0-9\s.,?!():;'\"]*$"

    if not re.match(allowed_chars_regex, regex):
        return "Error: Invalid characters in regex.  Only alphanumeric characters, spaces, and common punctuation are allowed.", 400  # Return a 400 Bad Request error

    if not re.match(allowed_chars_data, data):
        return "Error: Invalid characters in data. Only alphanumeric characters, spaces, and common punctuation are allowed.", 400  # Return a 400 Bad Request error

    #  Alternative:  If you *must* allow metacharacters, escape them:
    #  regex = re.escape(regex)  # This is safer than using the raw regex directly.
    #  However, disallowing them entirely is the *most* secure option.

    try:
        # Perform the regex search
        if re.search(regex, data):
            result = "Match found"
        else:
            result = "No match found"
    except re.error as e:
        return f"Error: Invalid regular expression: {e}", 400  # Handle regex errors

    # Sanitize output to prevent XSS.  Encode special characters.
    sanitized_result = html.escape(result)

    # Set the Content-Type header to specify encoding (UTF-8 is recommended)
    return sanitized_result, 200, {'Content-Type': 'text/plain; charset=utf-8'}


if __name__ == '__main__':
    app.run(debug=False)  # Never use debug mode in production!

