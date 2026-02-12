import yaml
from flask import Flask, request, jsonify
import logging
import secrets
import os
from jsonschema import validate, ValidationError, Draft7Validator
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Secret key for session management (if you were to use sessions)
# Generate a strong, random key and store it securely (e.g., environment variable)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    logging.critical("FLASK_SECRET_KEY environment variable not set.  Application will not start.")
    raise RuntimeError("FLASK_SECRET_KEY environment variable not set")


# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


# Define a schema for the expected payload
PAYLOAD_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["process_data", "other_action"]},
        "data": {"type": "string"},
        "user_id": {"type": "integer", "minimum": 1}
    },
    "required": ["action", "data", "user_id"],
    "additionalProperties": False  # Disallow unexpected keys
}


@app.route("/", methods=['POST'])
@limiter.limit("10/minute")  # Apply rate limiting to the endpoint
def handle_request():
    """
    Handles incoming POST requests.  Parses JSON payload and validates it.
    """
    try:
        if request.content_type != 'application/json':
            logging.warning(f"Invalid Content-Type: {request.content_type}")
            return jsonify({"error": "Invalid Content-Type.  Must be application/json"}), 400

        try:
            data = request.get_json()

            # Validate the payload against the schema
            try:
                validate(instance=data, schema=PAYLOAD_SCHEMA, cls=Draft7Validator)
            except ValidationError as e:
                logging.warning(f"Payload validation error: {e}")
                return jsonify({"error": "Invalid payload format"}, 400)

            # Sanitize input data (example - adapt to your specific needs)
            action = data.get("action", "").strip()
            data_value = data.get("data", "").strip()  # Rename to avoid shadowing
            user_id = data.get("user_id")

            # Reassign sanitized values (important!)
            data["action"] = action
            data["data"] = data_value


            # Process the payload (replace with your actual logic)
            logging.info(f"Received valid payload: {data}")
            return jsonify({"message": "Payload processed successfully"}), 200

        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
            return jsonify({"error": "An unexpected error occurred"}, 500)

    except Exception as e:
        logging.exception(f"An unexpected error occurred during request handling: {e}")
        return jsonify({"error": "An unexpected error occurred during request handling"}, 500)


if __name__ == "__main__":
    #  Do NOT use debug=True in production!  It can expose sensitive information.
    #  Use a proper WSGI server like gunicorn or uWSGI for production deployments.
    app.run(debug=False, host="0.0.0.0", port=5000)

