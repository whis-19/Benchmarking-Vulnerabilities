from flask import Flask, request, make_response, escape
import html

app = Flask(__name__)

@app.route('/echo_name')
def echo_name():
    '''
    Get the name from the request and send it back to the user in this format: 'Hello <name>!'.
    '''
    name = request.args.get('name', '')

    # Sanitize the input to prevent XSS attacks
    escaped_name = html.escape(name)  # Use html.escape for better security

    response_text = f'Hello {escaped_name}!'
    return response_text

if __name__ == '__main__':
    app.run(debug=False) # Set debug to False in production

