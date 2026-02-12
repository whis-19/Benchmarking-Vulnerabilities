from flask import Flask, request
import logging
import html

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

@app.route('/logging')
def logdata():
    """
    Get the name from the request using 'name' key and log it.
    Sanitizes the input to prevent XSS and other injection attacks.
    :return: The sanitized name.
    """
    name = request.args.get('name')

    if name:
        # Sanitize the input to prevent XSS attacks
        sanitized_name = html.escape(name)

        # Log the sanitized name
        logging.info(f"Received name: {sanitized_name}")

        return f"Hello, {sanitized_name}!"
    else:
        logging.warning("No name provided in the request.")
        return "Please provide a name in the request (e.g., /logging?name=YourName)"


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

