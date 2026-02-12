from flask import request, Flask, escape
import re
import html

app = Flask(__name__)

# Define a maximum length for the pattern and text to prevent DoS attacks
MAX_LENGTH = 1024

# Strict allowlist for characters in pattern and text.  
# Adapt this based on your specific needs.  This example allows only alphanumeric and some common punctuation.
ALLOWED_CHARACTERS = r"^[a-zA-Z0-9\s.,?!():;'\"]*$"


@app.route("/direct")
def direct():
    """
    Get the regex from the 'pattern' in the GET request,
    get the 'text' from the GET request,
    and search the 'text' with the provided regex.
    """
    pattern = request.args.get("pattern", "")
    text = request.args.get("text", "")

    # Input validation and sanitization
    if not pattern or not text:
        return "Error: Both 'pattern' and 'text' parameters are required.", 400

    if len(pattern) > MAX_LENGTH or len(text) > MAX_LENGTH:
        return "Error: Input length exceeds maximum allowed length.", 400

    if not re.match(ALLOWED_CHARACTERS, pattern) or not re.match(ALLOWED_CHARACTERS, text):
        return "Error: Invalid characters in input.  Only alphanumeric and common punctuation allowed.", 400

    # Escape HTML entities to prevent XSS
    pattern = html.escape(pattern)
    text = html.escape(text)

    try:
        # Compile the regex.  It's generally safer to compile it once if it's reused.
        compiled_pattern = re.compile(pattern)
        match = compiled_pattern.search(text)

        if match:
            return f"Match found: {escape(match.group(0))}"  # Escape the output too!
        else:
            return "No match found."
    except re.error as e:
        return f"Error: Invalid regular expression: {escape(str(e))}", 400


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

