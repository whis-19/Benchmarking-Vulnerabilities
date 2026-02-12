from flask import Flask, request, make_response, escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_SECRET_KEY'  # Replace with a strong, randomly generated key

@app.route('/')
def index():
    """Handles the root URL and prevents XSS vulnerabilities."""
    name = request.args.get("name", "World")

    # Input validation using an allowlist.  Only allow alphanumeric characters and spaces.
    if not all(c.isalnum() or c.isspace() for c in name):
        return "Invalid input. Only alphanumeric characters and spaces are allowed.", 400

    # Escape the output to prevent XSS.  Use escape() from Flask.
    escaped_name = escape(name)

    # Construct the response.
    message = f"Hello, {escaped_name}!"

    # Create a response object to set headers.
    response = make_response(message)

    # Set the Content-Type header to specify encoding.
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # Set the HttpOnly flag for the session cookie (if you're using sessions).
    # This example doesn't use sessions directly, but if you were, you'd do this:
    # response.set_cookie('session', 'your_session_id', httponly=True)

    return response


@app.route('/unsafe')
def unsafe():
    """Demonstrates an unsafe route vulnerable to XSS (DO NOT USE IN PRODUCTION)."""
    name = request.args.get("name", "World")
    message = f"Hello, {name}!"  # Vulnerable to XSS if name contains malicious code
    return message


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

