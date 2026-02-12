from flask import Flask, request, jsonify
import secrets
import sys
import io
import pickle
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
import secrets
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Secret key for signing cookies (important for security)
# Use os.urandom for cryptographically secure random numbers
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a strong, random key
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
)

class MyForm(FlaskForm):
    data = StringField('Data', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/unpickled', methods=['POST'])  # Use POST for data submission
@limiter.limit("10 per minute") # Example: Limit to 10 requests per minute
def unpickled():
    """
    Get the pickled data from the request using 'data' as the key.
    Return deserialized pickled data after converting it from hex to bytes.

    **CRITICAL SECURITY WARNING:  Deserializing untrusted data with pickle is EXTREMELY DANGEROUS.**
    **THIS CODE IS PROVIDED FOR DEMONSTRATION PURPOSES ONLY AND SHOULD NEVER BE USED IN A PRODUCTION ENVIRONMENT WITHOUT EXTENSIVE SECURITY REVIEW AND MITIGATION.**
    **IT IS VULNERABLE TO ARBITRARY CODE EXECUTION, EVEN WITH THE MITIGATIONS BELOW.  CONSIDER THIS CODE INSECURE BY DEFAULT.**

    **Mitigation (if you absolutely MUST use pickle):**

    1. **Authentication/Authorization:**  Ensure only trusted, authenticated, and authorized users can access this endpoint.  Implement robust access controls.
    2. **Input Validation:**  Strictly validate the *source* of the data.  Never accept pickle data from untrusted sources.  Treat all external data as potentially malicious.
    3. **Restricted Unpickling:**  Use `pickle.Unpickler` with a custom `find_class` method to restrict the classes that can be instantiated.  This is the most effective mitigation, but it's not foolproof.  Carefully curate the allowed classes.
    4. **Sandboxing:**  Run the unpickling process in a heavily sandboxed environment (e.g., using Docker with resource limits and a restricted seccomp profile, or a virtual machine) to limit the damage if exploitation occurs.  Monitor the sandbox closely.
    5. **Consider Alternatives:**  Use safer serialization formats like JSON or Protocol Buffers whenever possible.  These formats are much less vulnerable to arbitrary code execution.  Prefer schema-based serialization.
    6. **Logging and Monitoring:**  Log all requests, errors, and security-related events.  Monitor the system for suspicious activity.
    7. **Regular Security Audits:**  Conduct regular security audits of the code and infrastructure.

    """
    form = MyForm()
    if not form.validate_on_submit():
        logging.warning(f"Invalid form data: {form.errors}")
        return jsonify({"error": "Invalid form data", "errors": form.errors}), 400

    if request.method == 'POST':
        try:
            pickled_data_hex = form.data.data  # Get data from form (safer than request.data)

            if not pickled_data_hex:
                logging.warning("No data provided in request.")
                return jsonify({"error": "No data provided."}), 400

            # Input validation: Check if the hex data is valid
            if not all(c in '0123456789abcdef' for c in pickled_data_hex.lower()):
                logging.warning("Invalid hex data provided.")
                return jsonify({"error": "Invalid hex data."}), 400

            # Convert hex string to bytes
            try:
                pickled_data_bytes = bytes.fromhex(pickled_data_hex)
            except ValueError as e:
                logging.error(f"Error decoding hex data: {e}")
                return jsonify({"error": "Invalid hex data."}), 400

            # SECURITY WARNING:  This is the dangerous part.  DO NOT USE IN PRODUCTION WITHOUT EXTREME CAUTION.
            # Restrict unpickling to a safe subset of classes (example):
            class RestrictedUnpickler(pickle.Unpickler):
                def find_class(self, module, name):
                    # Only allow unpickling of specific safe classes
                    safe_modules = ['__main__', 'builtins']  # Example: allow classes from the current module and builtins
                    safe_classes = ['MySafeClass', 'int', 'str', 'list', 'dict', 'tuple'] # Example: allow these classes

                    if module in safe_modules and name in safe_classes:
                        logging.info(f"Allowing class: {module}.{name}")
                        return getattr(sys.modules[module], name)
                    # Forbid everything else.
                    logging.warning(f"Attempt to unpickle forbidden class: {module}.{name}")
                    raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))

            # Use the restricted unpickler
            try:
                data = RestrictedUnpickler(io.BytesIO(pickled_data_bytes)).load()
                logging.info("Unpickling successful.")
            except pickle.UnpicklingError as e:
                logging.error(f"Unpickling failed: {e}")
                return jsonify({"error": f"Unpickling failed: {str(e)}"}), 400
            except Exception as e:
                logging.error(f"An unexpected error occurred during unpickling: {e}")
                return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


            # data = pickle.loads(pickled_data_bytes)  # VERY DANGEROUS - DO NOT USE IN PRODUCTION

            # Sanitize output instead of directly converting to string
            try:
                if isinstance(data, MySafeClass):
                    result = str(data.value)  # Extract and sanitize
                    logging.info("Data sanitized and extracted successfully.")
                else:
                    result = "Data is not a MySafeClass or other allowed type."
                    logging.warning("Data is not an allowed type. Returning safe message.")

                return jsonify({"result": result}), 200
            except Exception as e:
                logging.error(f"Error sanitizing and extracting data: {e}")
                return jsonify({"error": "Error processing data."}), 500


        except Exception as e:
            logging.exception("An unexpected error occurred.") # Log the full traceback
            return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    else:
        logging.warning("Method not allowed.  Received a non-POST request.")
        return jsonify({"error": "Method not allowed. Use POST."}), 405

if __name__ == '__main__':
    # Example of a safe class (if you choose to use restricted unpickling)
    class MySafeClass:
        __slots__ = ['value']  # Restrict attribute assignment

        def __init__(self, value):
            self.value = value

        def __repr__(self):
            return f"MySafeClass({self.value})"

    # Example usage:
    # from your terminal:
    # python
    # import pickle
    # import requests
    # class MySafeClass:
    #     def __init__(self, value):
    #         self.value = value
    #     def __repr__(self):
    #         return f"MySafeClass({self.value})"
    # data = MySafeClass(123)
    # pickled_data = pickle.dumps(data)
    # pickled_data_hex = pickled_data.hex()
    # url = 'http://127.0.0.1:5000/unpickled'
    # data = {'data': pickled_data_hex}
    # response = requests.post(url, data=data)
    # print(response.text)

    app.run(debug=False)  # Disable debug mode in production!

