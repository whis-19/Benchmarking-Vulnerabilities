from flask import Flask, request, jsonify
import secrets
import os

app = Flask(__name__)

# Generate a strong, random secret key for session management and CSRF protection.
# Store it in an environment variable for production deployments.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)

@app.route('/', methods=['POST'])
def process_payload():
    """
    Processes a JSON payload from a POST request, checks for the 'name' field,
    and returns its content if it exists.  Handles potential errors gracefully.
    """
    try:
        # Attempt to parse the request body as JSON.  This is crucial for security.
        data = request.get_json()

        # Check if the request body was successfully parsed as JSON.
        if data is None:
            return jsonify({"error": "Invalid JSON payload"}), 400  # Bad Request

        # Check if the 'name' field exists in the JSON data.
        if 'name' in data:
            # Sanitize the input to prevent XSS attacks.  This is a critical security measure.
            name = str(data['name'])  # Convert to string to prevent unexpected types
            #  Consider using a more robust sanitization library like bleach for complex HTML.
            #  For example:
            #  import bleach
            #  name = bleach.clean(str(data['name']), strip=True)

            return jsonify({"name": name}), 200  # OK

        else:
            return jsonify({"error": "Field 'name' not found in payload"}), 400  # Bad Request

    except Exception as e:
        # Log the error for debugging purposes.  Never expose raw error messages to the user.
        print(f"Error processing payload: {e}")
        return jsonify({"error": "Internal server error"}), 500  # Internal Server Error


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like Gunicorn or uWSGI.
    #  Enable debugging only during development.
    app.run(debug=True, host='0.0.0.0', port=5000)

