from flask import Flask, request, make_response
import html

app = Flask(__name__)

@app.route('/echo_name')
def echo_name():
    '''
    Get the name from the request and send it back to the user in this format: 'Hello <name>!'.
    Sanitizes the input to prevent Cross-Site Scripting (XSS) attacks and validates input length.
    '''
    name = request.args.get('name', '')

    # Input Validation: Limit name length
    if len(name) > 100:
        return "Name too long", 400

    # Optionally, filter out characters:
    # name = ''.join(c for c in name if c.isalnum() or c in ' ') # Allow alphanumeric and spaces

    # Use html.escape for robust XSS prevention
    escaped_name = html.escape(name)

    response_text = f"Hello {escaped_name}!"

    # Add a basic CSP header (adjust as needed for your application)
    response = make_response(response_text)
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    return response

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

