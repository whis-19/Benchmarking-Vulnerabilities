from flask import Flask, request, make_response, escape
import html

app = Flask(__name__)

@app.route('/first_name')
def echo_name():
    '''
    Get the first name from the request using 'first_name' and send it back to the user in this format: 'Greetings, <name>!'.
    '''
    first_name = request.args.get('first_name', '')

    # Sanitize the input to prevent XSS attacks
    safe_name = html.escape(first_name)

    # Construct the greeting
    greeting = f"Greetings, {safe_name}!"

    # Create the response
    response = make_response(greeting)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Set content type for security

    return response

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

