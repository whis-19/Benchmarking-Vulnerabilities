from flask import request, Flask, escape
import re
import html

app = Flask(__name__)

@app.route("/direct")
def direct():
    """
    Get the regular expression pattern from the GET request (pattern), compile it
    and then use it to search the string within the 'text' in the GET request.
    """
    pattern = request.args.get('pattern', '')
    text = request.args.get('text', '')

    # Validate and sanitize inputs
    if not pattern or not text:
        return "Error: Both 'pattern' and 'text' parameters are required.", 400

    # 1. Input Validation:  Limit the complexity of the regex.  This is a crucial security measure.
    #    A complex regex can lead to denial-of-service (ReDoS) attacks.
    if len(pattern) > 100:  # Limit the length of the regex pattern
        return "Error: Pattern too long.  Maximum length is 100 characters.", 400

    # 2. Input Validation:  Restrict the character set of the regex.  This prevents injection of malicious regex.
    #    Allow only alphanumeric characters, spaces, and a limited set of safe special characters.
    allowed_pattern_chars = r"^[a-zA-Z0-9\s\+\-\*\/\(\)\[\]\{\}\^\$\?\|\\\.]*$"  # Added \. for literal dot
    if not re.match(allowed_pattern_chars, pattern):
        return "Error: Invalid characters in pattern.  Only alphanumeric characters, spaces, and a limited set of special characters are allowed.", 400

    # 3. Input Validation:  Limit the length of the text to search.
    if len(text) > 1000:
        return "Error: Text too long. Maximum length is 1000 characters.", 400

    # 4. Escape HTML in the text to prevent XSS.  This is essential because the output is displayed in a web page.
    text = html.escape(text)

    try:
        # Compile the regular expression.  It's good practice to compile it once if it's used multiple times.
        # Use re.escape to escape any special characters in the pattern.  This prevents regex injection.
        compiled_pattern = re.compile(pattern)  # No need to escape here, validation handles it

        # Search the text using the compiled pattern.
        match = compiled_pattern.search(text)

        if match:
            return f"Match found: {html.escape(str(match.group(0)))}" # Escape the match to prevent XSS
        else:
            return "No match found."

    except re.error as e:
        return f"Error: Invalid regular expression: {escape(str(e))}", 400 # Escape the error message

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

