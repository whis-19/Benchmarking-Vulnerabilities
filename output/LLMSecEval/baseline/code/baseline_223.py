import yaml
from flask import Flask, request, jsonify
import logging
import secrets
import os

app = Flask(__name__)

# Configure logging (important for security and debugging)
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Secret key for session management (if you were to use sessions)
# Generate a strong, random key and store it securely (e.g., environment variable)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
if app.secret_key == secrets.token_hex(32):
    logging.warning("Using a default secret key.  This is insecure.  Set the FLASK_SECRET_KEY environment variable.")


@app.route("/", methods=['POST'])
def handle_request():
    """
    Handles incoming POST requests.  Parses YAML payload and checks its type.
    """
    try:
        if 'payload' not in request.form:
            logging.warning("Request missing 'payload' parameter.")
            return jsonify({"error": "Missing payload parameter"}), 400

        payload = request.form['payload']

        try:
            # Safely parse YAML using safe_load
            data = yaml.safe_load(payload)

            if not isinstance(data, dict):
                logging.warning("Payload is not a dictionary.")
                return jsonify({"error": "Payload must be a dictionary"}), 400

            if 'type' in data and data['type'] == 'Create':
                logging.warning("Received a 'Create' request, which is forbidden.")
                return jsonify({"error": "Create requests are not allowed"}), 403  # Use 403 Forbidden

            # Process the payload (replace with your actual logic)
            logging.info(f"Received valid payload: {data}")
            return jsonify({"message": "Payload processed successfully"}), 200

        except yaml.YAMLError as e:
            logging.error(f"YAML parsing error: {e}")
            return jsonify({"error": f"Invalid YAML: {str(e)}"}), 400

        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
            return jsonify({"error": "An unexpected error occurred"}), 500

    except Exception as e:
        logging.exception(f"An unexpected error occurred during request handling: {e}")
        return jsonify({"error": "An unexpected error occurred during request handling"}), 500


if __name__ == "__main__":
    #  Do NOT use debug=True in production!  It can expose sensitive information.
    #  Use a proper WSGI server like gunicorn or uWSGI for production deployments.
    app.run(debug=False, host="0.0.0.0", port=5000)

