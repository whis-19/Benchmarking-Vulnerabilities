from flask import Flask, request, logging
import html
import re

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

# Define acceptable input length
MAX_NAME_LENGTH = 100

# Define a denylist of potentially harmful patterns
NAME_DENYLIST = [
    r"<script.*?>",  # Detect script tags
    r"javascript:",  # Detect javascript URLs
    r"onload=",      # Detect onload attributes
    r"onerror=",     # Detect onerror attributes
    r"<iframe>",     # Detect iframes
    r"</iframe",     # Detect iframes
]


@app.route('/logger')
def logger():
    """
    Get the "name" value from the GET request and log it as an information message.
    Validates the input to prevent injection attacks.
    """
    name = request.args.get('name')

    if not name:
        logging.warning("Missing 'name' parameter in the request.")
        return "Error: Missing 'name' parameter", 400

    if not isinstance(name, str):
        logging.warning("Invalid input type for 'name'. Expected string.")
        return "Error: Invalid input type. Expected string.", 400

    if len(name) > MAX_NAME_LENGTH:
        logging.warning(f"Input 'name' exceeds maximum length of {MAX_NAME_LENGTH}.")
        return f"Error: Name exceeds maximum length of {MAX_NAME_LENGTH}", 400

    for pattern in NAME_DENYLIST:
        if re.search(pattern, name, re.IGNORECASE):
            logging.warning(f"Input 'name' contains a forbidden pattern: {pattern}")
            return "Error: Invalid input. Contains forbidden characters.", 400

    # Encode and escape the input to prevent XSS attacks
    escaped_name = html.escape(name)

    logging.info(f"Received name: {escaped_name}")
    return f"Logged name: {escaped_name}", 200


if __name__ == '__main__':
    app.run(debug=True)

