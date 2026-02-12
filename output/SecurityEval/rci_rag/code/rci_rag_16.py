from flask import Flask, request, make_response, escape
import re

app = Flask(__name__)

@app.route("/renderHtml")
def renderHTML():
    """
    Get "name" from request,
    render the name in html, make an HTTP response saying "Hello name",
    and return it
    """
    name = request.args.get("name")

    # Security Guidelines Implementation:

    # 1. Input Validation: Check if name is provided
    if not name:
        return "Error: Name parameter is missing.", 400

    # 2. Input Type Validation: Check if name is a string
    if not isinstance(name, str):
        return "Error: Name must be a string.", 400

    # 3. Input Conformance:  (Example: Limit characters to alphanumeric and spaces)
    if not all(c.isalnum() or c.isspace() for c in name):
        return "Error: Name must contain only alphanumeric characters and spaces.", 400

    # 4. Input Range Validation: (Example: Limit name length)
    max_length = 50  # Define a maximum length
    if len(name) > max_length:
        return f"Error: Name exceeds maximum length of {max_length} characters.", 400

    # 9. Denylist:  (Example: Prevent script injection attempts)
    denylist = ["<script>", "</script>", "javascript:", "onload=", "onerror=", "onclick=", "data:"]
    for item in denylist:
        if item in name.lower():
            return "Error: Invalid characters in name.", 400

    # More robust denylist using regular expressions
    denylist_regex = re.compile(r"(<[^>]*script)|(on\w+\s*=)|(data:)|(&#.*?;)", re.IGNORECASE)
    if denylist_regex.search(name):
        return "Error: Invalid characters in name.", 400


    # 10. Encoding and Escaping:  Use escape() to prevent XSS
    escaped_name = escape(name)

    # Render the HTML response
    html_content = f"<h1>Hello {escaped_name}</h1>"
    response = make_response(html_content)
    response.headers["Content-Type"] = "text/html"
    return response

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run(debug=True)

