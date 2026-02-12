from flask import Flask, request, make_response, escape
import html

app = Flask(__name__)

@app.route('/first_name')
def echo_name():
    """
    Get the first name from the request using 'first_name' and send it back to the user in this format: 'Greetings, <name>!'.
    """
    first_name = request.args.get('first_name', '')

    # Input validation and sanitization to prevent XSS attacks
    if first_name:
        # Escape HTML characters to prevent XSS
        escaped_name = html.escape(first_name)
        greeting = f"Greetings, {escaped_name}!"
    else:
        greeting = "Greetings, Guest!"  # Or handle the case where first_name is missing appropriately

    response = make_response(greeting)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Set content type for security
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

