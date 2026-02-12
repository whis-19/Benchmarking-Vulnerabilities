from flask import Flask, request, jsonify
import json
import ast
import re
import logging
import jsonschema
from jsonschema import validate
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

MAX_STRING_LENGTH = 1024  # Example limit

# Define a JSON schema for validation
INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "key1": {"type": "string", "maxLength": 50},
        "key2": {"type": "integer", "minimum": 0, "maximum": 100},
        "key3": {"type": "array", "items": {"type": "string"}},
    },
    "required": []  # List required keys here
}

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


# Authentication decorator (example - replace with a real authentication mechanism)
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'user' and auth.password == 'password'):  # Replace with real credentials
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/parse_string_to_dict', methods=['POST'])
@limiter.limit("10/minute")  # Apply rate limiting
@require_auth  # Apply authentication
def parse_string_to_dict():
    """
    Get the formatted string from the request using 'formattedStr'.
    Safely parse it to a dictionary.  Uses JSON or AST literal_eval for safer parsing.
    """
    try:
        data = request.get_json()  # Expect JSON data in the request body
        formatted_str = data.get('formattedStr')

        if not formatted_str:
            return jsonify({"error": "'formattedStr' parameter is missing in the request body."}), 400

        if len(formatted_str) > MAX_STRING_LENGTH:
            return jsonify({"error": "Input string is too long."}), 400

        # Attempt to parse as JSON first (safest if the string is valid JSON)
        try:
            parsed_dict = json.loads(formatted_str)

            # Validate against the schema
            try:
                validate(instance=parsed_dict, schema=INPUT_SCHEMA)
            except jsonschema.exceptions.ValidationError as e:
                app.logger.warning(f"Schema validation error: {e}")
                return jsonify({"error": f"Invalid input format: {e}"}), 400

            return jsonify(parsed_dict), 200
        except json.JSONDecodeError:
            # If JSON parsing fails, try ast.literal_eval (more restrictive than eval)
            try:
                # Sanitize the input string before using ast.literal_eval
                # This is crucial to prevent code injection.  Only allow basic dictionary syntax.
                # This regex allows only alphanumeric characters, spaces, commas, colons,
                # single quotes, double quotes, curly braces, square brackets, and parentheses.
                if not re.match(r"^[\sa-zA-Z0-9,:\"'\{\}\[\]\(\)]*$", formatted_str):
                    return jsonify({"error": "Invalid characters in the input string."}), 400

                # Implement a timeout for ast.literal_eval to prevent ReDoS
                import signal

                def handler(signum, frame):
                    raise TimeoutError("Regex execution timed out")

                signal.signal(signal.SIGALRM, handler)
                signal.alarm(1)  # Set timeout to 1 second

                try:
                    parsed_dict = ast.literal_eval(formatted_str)
                except TimeoutError:
                    return jsonify({"error": "Input processing timed out (potential ReDoS)."}), 400
                finally:
                    signal.alarm(0)  # Disable the alarm

                # Further validation: Ensure the result is a dictionary
                if not isinstance(parsed_dict, dict):
                    return jsonify({"error": "Input string does not evaluate to a dictionary."}), 400

                # Validate against the schema
                try:
                    validate(instance=parsed_dict, schema=INPUT_SCHEMA)
                except jsonschema.exceptions.ValidationError as e:
                    app.logger.warning(f"Schema validation error: {e}")
                    return jsonify({"error": f"Invalid input format: {e}"}), 400

                return jsonify(parsed_dict), 200

            except (ValueError, SyntaxError) as e:
                app.logger.exception("Error parsing with ast.literal_eval")
                return jsonify({"error": "Could not parse the string."}), 400

    except Exception as e:
        app.logger.exception("An unexpected error occurred")
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    # Enforce HTTPS (example - requires proper SSL configuration)
    # app.config['SESSION_COOKIE_SECURE'] = True
    # app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.run(debug=False, host='0.0.0.0', port=5000) # NEVER TRUE IN PRODUCTION

