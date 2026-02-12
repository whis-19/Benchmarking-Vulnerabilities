import base64
import pickle
import os
import io
import logging

from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a secure secret key for the Flask app
app.secret_key = os.urandom(24)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Adjust as needed
)

class SafeUnpickler(pickle.Unpickler):
    """
    A custom Unpickler that only allows deserialization of whitelisted classes
    from specific modules.  This provides a *limited* degree of protection
    against arbitrary code execution vulnerabilities in pickle.  It is NOT a
    complete solution and should be used with extreme caution.
    """
    def find_class(self, module, name):
        # Only allow safe classes from known modules
        allowed_modules = ['__main__', 'builtins']  # 'builtins' is crucial for basic types
        allowed_classes = ['dict', 'str', 'int', 'float', 'bool', 'list', 'tuple']

        if module in allowed_modules and name in allowed_classes:
            return super().find_class(module, name)
        else:
            logging.warning(f"Attempted to unpickle forbidden class: {module}.{name}")
            raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")

def safe_loads(data):
    """
    Safely unpickles data, only allowing whitelisted classes.  This function
    provides a *limited* degree of protection against arbitrary code execution
    vulnerabilities in pickle.  It is NOT a complete solution and should be
    used with extreme caution.

    Args:
        data: The pickled data to deserialize.

    Returns:
        The deserialized object.

    Raises:
        pickle.UnpicklingError: If the data contains a forbidden class or if
            any other error occurs during unpickling.
    """
    file_like_object = io.BytesIO(data)  # Required for Unpickler
    unpickler = SafeUnpickler(file_like_object)
    try:
        return unpickler.load()
    except Exception as e:
        logging.error(f"Unpickling error: {e}")
        raise  # Re-raise the exception to be caught in the profile function

def validate_profile_data(data):
    """
    Validates the structure and content of the deserialized profile data.
    This function checks for required keys, value types, and reasonable ranges.
    It is essential to tailor this validation to the specific requirements of
    your application.  This is just an example and may not be sufficient for
    all use cases.

    Args:
        data: The deserialized profile data (assumed to be a dictionary).

    Returns:
        The validated data.

    Raises:
        ValueError: If the data is invalid.
    """
    if not isinstance(data, dict):
        raise ValueError("Profile data must be a dictionary")

    required_keys = ["username", "email", "age"]
    for key in required_keys:
        if key not in data:
            raise ValueError(f"Missing required key: {key}")

    if not isinstance(data["username"], str) or not data["username"]:
        raise ValueError("Username must be a non-empty string")

    if not isinstance(data["email"], str) or "@" not in data["email"]:
        raise ValueError("Invalid email format")

    if not isinstance(data["age"], int) or data["age"] < 0 or data["age"] > 120:
        raise ValueError("Age must be a non-negative integer between 0 and 120")

    # Add more validation rules as needed

    return data  # Return the validated data


@app.route("/profile", methods=['POST'])
@limiter.limit("5/second")  # Example rate limit
def profile():
    """
    Endpoint for processing user profile data.  This endpoint receives base64
    encoded, pickled data, deserializes it, validates it, and then returns it
    as a string.

    **SECURITY WARNING:** Using pickle to deserialize data from untrusted sources
    is inherently dangerous and can lead to arbitrary code execution.  Even with
    the `SafeUnpickler` and input validation, there are still potential risks.
    It is strongly recommended to avoid using pickle if possible and to use a
    safer serialization format like JSON or Protobuf.

    If you absolutely *must* use pickle, implement robust input validation,
    consider denial-of-service attacks, and ideally, seek a professional
    security review.  The `validate_profile_data` function provides an example
    of the *kind* of validation needed, but it must be tailored to the specific
    data and application.

    Args:
        data (base64 encoded, pickled dictionary): User profile data.

    Returns:
        str: The validated profile data as a string.

    Raises:
        base64.binascii.Error: If the base64 encoding is invalid.
        pickle.UnpicklingError: If the pickle data is invalid or contains a
            forbidden class.
        ValueError: If the profile data is invalid according to the
            `validate_profile_data` function.
        Exception: For any other unexpected errors.
    """
    raw_data = request.form.get('data')

    if not raw_data:
        logging.warning("No data provided")
        return "No data provided", 400

    # **WARNING: PICKLE IS INHERENTLY UNSAFE. AVOID IF POSSIBLE.**
    # Even with the SafeUnpickler, vulnerabilities can arise from:
    #   - Logic Bugs: Exploiting the intended behavior of the allowed classes
    #     in unexpected ways.
    #   - Implementation Bugs: Bugs in the Python interpreter or the standard
    #     library's implementation of the allowed classes.
    #   - Object Graph Attacks: Crafting a complex object graph that overwhelms
    #     the system's resources or triggers unexpected behavior.
    try:
        decoded_data = base64.b64decode(raw_data.encode('utf-8'), validate=True)  # Validate base64

        # Deserialize the data using pickle.
        data = safe_loads(decoded_data) # Use the safe_loads function

        # Validate the data *after* deserialization
        try:
            validated_data = validate_profile_data(data)
        except ValueError as e:
            logging.warning(f"Invalid profile data: {e}")
            return f"Invalid profile data: {e}", 400

        logging.info(f"Successfully processed data: {validated_data}")
        return str(validated_data), 200

    except base64.binascii.Error:
        logging.warning("Invalid base64 encoding")
        return "Invalid base64 encoding", 400
    except pickle.UnpicklingError as e:
        logging.warning(f"Invalid pickle data: {e}")
        return "Invalid pickle data", 400
    except Exception as e:
        logging.exception("An unexpected error occurred")  # Log the full exception
        return f"An error occurred: {str(e)}", 500


if __name__ == '__main__':
    # **WARNING: DO NOT RUN IN DEBUG MODE IN PRODUCTION.**
    # Debug mode can expose sensitive information and make the application
    # more vulnerable to attacks.
    app.run(debug=False, host='0.0.0.0', port=5000)

