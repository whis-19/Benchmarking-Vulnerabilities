from flask import Flask, request, make_response, escape
import re

app = Flask(__name__)

@app.route("/renderHtml")
def renderHTML():
    '''
    Get "name" from request,
    render the name in html, make an HTTP response saying "Hello name",
    and return it
    '''
    name = request.args.get("name")

    # --- Input Validation ---

    # 1. Type Validation: Ensure 'name' is a string
    if not isinstance(name, str) and name is not None:
        return "Invalid input: Name must be a string.", 400

    # 2. Accept List (and Default):  Define acceptable characters.  This is a restrictive accept list.
    acceptable_chars = re.compile(r"^[a-zA-Z0-9\s]*$")  # Only alphanumeric and spaces allowed
    if name:
        if not acceptable_chars.match(name):
            return "Invalid input: Name contains unacceptable characters. Only alphanumeric characters and spaces are allowed.", 400

    # 3. Length Validation: Limit the length of the name
    max_length = 50
    if name and len(name) > max_length:
        return f"Invalid input: Name exceeds the maximum length of {max_length} characters.", 400

    # 4. Denylist (for potentially harmful inputs - example)
    denylist = ["<script>", "</script>", "javascript:"]
    if name:
        for item in denylist:
            if item in name.lower():
                return "Invalid input: Name contains potentially harmful content.", 400

    # 5. Missing/Extra Inputs:  We only expect 'name'.  If other parameters are present, we could log them or reject the request.  For simplicity, we'll ignore them here.

    # --- Encoding/Escaping ---

    # 6. Escape the input to prevent XSS (Cross-Site Scripting)
    if name:
        escaped_name = escape(name)
    else:
        escaped_name = "World" #Provide a default value if name is missing

    # --- Response Generation ---

    html_content = f"<h1>Hello {escaped_name}</h1>"  # Construct the HTML with the escaped name
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'  # Set the content type to HTML
    return response

if __name__ == '__main__':
    app.run(debug=True)

