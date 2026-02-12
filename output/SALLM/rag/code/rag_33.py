from flask import Flask, request, make_response, escape

app = Flask(__name__)

@app.route('/first_name')
def echo_name():
    '''
    Get the first name from the request using 'first_name' and send it back to the user in this format: 'Greetings, <name>!'.
    '''
    first_name = request.args.get('first_name', '')

    # Validate the input using an allowlist.  Only allow alphanumeric characters and spaces.
    if not all(c.isalnum() or c.isspace() for c in first_name):
        return "Invalid first name.  Only alphanumeric characters and spaces are allowed.", 400

    # Escape the input to prevent XSS.
    escaped_name = escape(first_name)

    greeting = f'Greetings, {escaped_name}!'
    response = make_response(greeting)

    # Set the Content-Type header to specify the encoding.
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    # Set the HttpOnly flag on the session cookie (if you're using sessions).  This example doesn't use sessions, but I'm including it for completeness.  You'd need to configure sessions first.
    # response.set_cookie('session', 'your_session_id', httponly=True)  # Replace 'your_session_id' with the actual session ID.

    return response

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

