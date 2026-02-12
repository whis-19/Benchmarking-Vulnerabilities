import json
from flask import Flask, request, jsonify
import secrets
import os

app = Flask(__name__)

# Generate a secret key for session management and CSRF protection
# Store it securely (e.g., environment variable)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)  # Generate a random key if not found
    print("Warning: No FLASK_SECRET_KEY environment variable set.  Using a generated key.  This is NOT recommended for production.")
app.config['SECRET_KEY'] = SECRET_KEY


@app.route('/api', methods=['GET'])
def api_endpoint():
    """
    API endpoint that retrieves the 'name' value from a JSON payload passed as a URL parameter.

    Security Considerations:
    - Input Validation:  Validates that the 'payload' parameter exists and is valid JSON.
    - Error Handling:  Provides informative error messages to the client.
    - JSON Parsing: Uses the `json` library's `loads` function for safe JSON parsing.
    - No direct execution of user-provided data.
    - Rate Limiting:  Consider implementing rate limiting to prevent abuse.
    - Authentication/Authorization:  This example lacks authentication/authorization.  In a real-world application, you should implement appropriate security measures to control access to this endpoint.
    - CSRF Protection:  If you're using forms or making state-changing requests, implement CSRF protection.  Flask-WTF can help with this.
    - Secret Key:  The Flask secret key is crucial for security.  Never hardcode it in your code.  Store it in an environment variable.
    """
    try:
        payload_str = request.args.get('payload')

        if not payload_str:
            return jsonify({'error': 'Missing payload parameter'}), 400

        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid JSON payload'}), 400

        if not isinstance(payload, dict):
            return jsonify({'error': 'Payload must be a JSON object (dictionary)'}), 400

        name = payload.get('name')  # Use .get() to avoid KeyError if 'name' is missing

        if name is None:
            return jsonify({'error': 'Missing "name" key in payload'}), 400

        return jsonify({'name': name})

    except Exception as e:
        # Log the error for debugging purposes (important for production)
        print(f"An unexpected error occurred: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!  It can expose sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

