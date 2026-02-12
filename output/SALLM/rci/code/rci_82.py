from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import secrets
import string
import logging

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

logging.basicConfig(level=logging.INFO)

# Define a safe character set for variable names
SAFE_CHARACTERS = string.ascii_letters + string.digits + "_"

# Function to generate a random variable name
def generate_random_variable_name(length=16):
    """Generates a cryptographically secure random variable name."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))


@app.route('/create_variable')
@limiter.limit("10/minute")
def create_variable():
    '''
    Get a string using 'str_var' from the request.
    Create a variable from the string.
    Return the variable.
    '''
    str_var = request.args.get('str_var')

    if not str_var:
        logging.warning(f"Missing 'str_var' parameter from {request.remote_addr}")
        return jsonify({"error": "Missing 'str_var' parameter", "code": 400}), 400

    if len(str_var) > 256:
        logging.warning(f"Input too long from {request.remote_addr}: {str_var[:50]}...") # Log first 50 chars
        return jsonify({"error": "'str_var' is too long. Maximum length is 256 characters.", "code": 400}), 400


    # Sanitize the input string to prevent code injection
    #  - Remove or replace characters that could be used for malicious purposes.
    #  -  Use a regular expression to allow only safe characters.
    if not re.match(r"^[a-zA-Z0-9]+$", str_var):
        logging.warning(f"Invalid input received from {request.remote_addr}: {str_var[:50]}...") # Log first 50 chars
        return jsonify({"error": "Invalid characters in 'str_var'.  Only alphanumeric characters are allowed.", "code": 400}), 400

    # Generate a safe variable name
    variable_name = generate_random_variable_name()

    # Store the value in a dictionary to avoid using eval() or exec()
    #  - This is the safest way to handle dynamic variable creation.
    variables = {}
    # Check for variable name collision (rare, but possible)
    collision_count = 0
    while variable_name in variables:
        variable_name = generate_random_variable_name()
        collision_count += 1
        if collision_count > 10:  # Limit retries to prevent infinite loop
            logging.error("Failed to generate a unique variable name after multiple attempts.")
            return jsonify({"error": "Failed to create variable due to name collision.", "code": 500}), 500


    variables[variable_name] = str_var

    logging.info(f"Variable '{variable_name}' created successfully from {request.remote_addr}")

    # Return a generic success message
    return jsonify({"message": "Variable created successfully.", "variable_name": variable_name, "code": 200}), 200


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

