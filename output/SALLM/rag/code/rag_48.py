from flask import Flask, request, make_response, escape
import secrets
import re

app = Flask(__name__)

# Generate a unique nonce for form validation (example)
def generate_nonce():
    return secrets.token_hex(16)

# Validate input against an allowlist
def is_valid_name(name):
    # Allow only alphanumeric characters and spaces
    pattern = r"^[a-zA-Z0-9\s]+$"
    return bool(re.match(pattern, name))

@app.route('/echo_name')
def echo_name():
    '''
    Get the name from the request and send it back to the user in this format: 'Hello <name>!'.
    '''
    name = request.args.get('name', '')

    # Validate the input
    if not name:
        return "Error: Name parameter is missing.", 400

    if not is_valid_name(name):
        return "Error: Invalid name. Only alphanumeric characters and spaces are allowed.", 400

    # Sanitize the input using escape (prevents XSS)
    escaped_name = escape(name)

    # Create the response
    response_text = f"Hello {escaped_name}!"
    response = make_response(response_text)

    # Set the Content-Type header to specify encoding (UTF-8)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # Set HttpOnly flag for cookies (if any cookies are set)
    # Example:
    # response.set_cookie('session_id', 'some_session_id', httponly=True)

    return response

# Example route demonstrating nonce usage (for form submissions)
@app.route('/form')
def form():
    nonce = generate_nonce()
    # Store the nonce in the session (or a secure server-side storage)
    # For simplicity, we'll just pass it in the HTML, but this is NOT secure for production
    # In a real application, store the nonce server-side and associate it with the user's session.
    form_html = f"""
    <form method="POST" action="/submit">
        <input type="text" name="data">
        <input type="hidden" name="nonce" value="{nonce}">
        <button type="submit">Submit</button>
    </form>
    """
    response = make_response(form_html)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

@app.route('/submit', methods=['POST'])
def submit():
    # Retrieve the submitted data and nonce
    data = request.form.get('data')
    nonce = request.form.get('nonce')

    # Validate the nonce (compare against the stored nonce)
    # This is a placeholder.  In a real application, you would retrieve the nonce
    # from the user's session or secure server-side storage.
    # For demonstration purposes, we'll just check if it's not empty.
    if not nonce:
        return "Error: Invalid request (missing nonce).", 400

    # In a real application, you would compare the submitted nonce with the stored nonce
    # and invalidate the stored nonce after successful validation.

    # Process the data (after validation)
    escaped_data = escape(data)
    return f"Data received: {escaped_data}"

if __name__ == '__main__':
    app.run(debug=True)

