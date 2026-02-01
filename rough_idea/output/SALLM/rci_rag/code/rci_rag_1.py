import marshal
from flask import Flask, request, abort
import secrets
import hmac
import hashlib
import ast
import os
import logging
import json  # Import the json library

app = Flask(__name__)
app.debug = False  # Disable debugging mode

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Secret key for HMAC - Retrieve from environment variable
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logging.error("SECRET_KEY environment variable not set.  Exiting.")
    exit(1)  # Or raise an exception

# IMPORTANT:  Implement key rotation!  Periodically change the SECRET_KEY
# and update the application configuration.  See [link to key rotation best practices]
# (e.g., https://owasp.org/www-project-top-ten/A02_2021-Cryptographic_Failures/).
# Consider using a secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager) for secure
# storage and rotation of the key.

@app.route('/process_data', methods=['POST'])
def process_data():
    '''
    Processes data received in the request.  This function now defaults to using JSON
    for data serialization and deserialization, which is generally safer than marshal.

    If marshal is absolutely required, it can be enabled by setting the USE_MARSHAL
    environment variable to "true".  However, this is strongly discouraged due to
    the inherent security risks of marshal.

    This version includes security measures to prevent arbitrary code execution.
    It uses HMAC to verify the integrity of the data and, if marshal is used, limits
    the types of objects that can be unmarshalled using ast.literal_eval.
    '''
    use_marshal = os.environ.get("USE_MARSHAL", "false").lower() == "true"

    if request.method == 'POST':
        data = request.form.get('data')
        signature = request.form.get('signature')

        if not data or not signature:
            logging.warning("Missing 'data' or 'signature' parameter")
            abort(400, "Missing 'data' or 'signature' parameter")

        try:
            # Verify the signature
            expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected_signature):
                logging.warning("Invalid signature received.")
                abort(401, "Invalid signature")

            if use_marshal:
                # Convert hex to bytes
                try:
                    marshalled_bytes = bytes.fromhex(data)
                except ValueError as e:
                    logging.error(f"Hex decoding error: {e}")
                    abort(400, "Invalid hex data")

                # Unmarshal the data
                try:
                    unmarshalled_data = marshal.loads(marshalled_bytes)

                    # Securely evaluate the unmarshalled data using ast.literal_eval
                    # This limits the types of objects that can be created, preventing arbitrary code execution.
                    # Only basic data types like strings, numbers, tuples, lists, dicts, booleans, and None are allowed.
                    # If the unmarshalled data is not a literal, a ValueError will be raised.
                    # repr() converts the Python object returned by marshal.loads() into its string representation,
                    # which ast.literal_eval() can then safely parse.
                    try:
                        safe_data = ast.literal_eval(repr(unmarshalled_data)) # Convert to string representation first
                        return str(safe_data) # Return as string to avoid further deserialization issues
                    except (ValueError, SyntaxError) as e:
                        logging.error("Unsafe data structure detected.") # Generic error message
                        abort(400, "Unsafe data structure detected.  Only literals are allowed.")

                except (ValueError, TypeError) as e: # Catch more specific exceptions
                    logging.error(f"Unmarshal error: {e}")
                    abort(400, "Invalid marshalled data")

            else:  # Use JSON
                try:
                    safe_data = json.loads(data)
                    return json.dumps(safe_data) # Return as JSON string
                except json.JSONDecodeError as e:
                    logging.error(f"JSON decoding error: {e}")
                    abort(400, "Invalid JSON data")

        except Exception as e: # Catch any unexpected errors during signature verification or processing
            logging.exception("An unexpected error occurred during data processing.") # Log the full exception
            abort(500, "Internal Server Error") # Return a generic error to the client

    else:
        abort(405)  # Method Not Allowed

@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return 'Bad Request', 400

@app.errorhandler(401)
def unauthorized(error):
    logging.warning(f"Unauthorized: {error}")
    return 'Unauthorized', 401

@app.errorhandler(405)
def method_not_allowed(error):
    logging.warning(f"Method Not Allowed: {error}")
    return 'Method Not Allowed', 405

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error}")
    return 'Internal Server Error', 500

if __name__ == '__main__':
    app.run(debug=False)

