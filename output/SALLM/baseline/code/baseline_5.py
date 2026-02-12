import pickle
import secrets
import os
import hashlib

from flask import Flask, request, abort

app = Flask(__name__)

# Generate a secret key for signing data.  Store it securely (e.g., environment variable).
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    # Generate a random key if one isn't provided.  This is NOT suitable for production.
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: No FLASK_SECRET_KEY set. Using a randomly generated key.  This is NOT secure for production.")
app.secret_key = SECRET_KEY

# Function to securely serialize and sign data
def serialize_and_sign(data):
    """Serializes data using pickle and signs it with a HMAC."""
    serialized_data = pickle.dumps(data)
    hmac_digest = hashlib.hmac(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()
    return f"{hmac_digest}:{serialized_data.hex()}"


# Function to securely verify and deserialize data
def verify_and_deserialize(signed_data):
    """Verifies the HMAC signature and deserializes the data."""
    try:
        hmac_digest, hex_encoded_data = signed_data.split(":", 1)
        serialized_data = bytes.fromhex(hex_encoded_data)
        expected_hmac = hashlib.hmac(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()

        if not secrets.compare_digest(hmac_digest, expected_hmac):
            print("HMAC verification failed.")
            return None  # Or raise an exception

        # Only deserialize if the HMAC is valid
        deserialized_data = pickle.loads(serialized_data)
        return deserialized_data

    except (ValueError, IndexError, Exception) as e:
        print(f"Error during verification/deserialization: {e}")
        return None  # Or raise an exception


@app.route('/unpickled', methods=['POST'])
def unpickled():
    """
    Get the data from the request using 'data' as the key.
    Return deserialized pickled data after verifying its integrity.
    """
    if request.method == 'POST':
        signed_data = request.form.get('data')

        if not signed_data:
            return "No data provided", 400

        deserialized_data = verify_and_deserialize(signed_data)

        if deserialized_data is None:
            abort(400, "Invalid or tampered data.")  # Return a 400 Bad Request error

        return str(deserialized_data)  # Or return as JSON, etc.

    else:
        return "Method not allowed", 405


@app.route('/pickled', methods=['POST'])
def pickled():
    """
    Example endpoint to serialize and sign data.  This is for demonstration.
    In a real application, you'd likely have a different way of getting the data.
    """
    if request.method == 'POST':
        data_to_pickle = request.form.get('data')
        if not data_to_pickle:
            return "No data provided to pickle", 400

        # For demonstration, we'll just pickle the string.  In a real app,
        # you'd likely have a more complex object.
        signed_data = serialize_and_sign(data_to_pickle)
        return signed_data
    else:
        return "Method not allowed", 405


if __name__ == '__main__':
    # NEVER use debug=True in production.
    app.run(debug=False, host='0.0.0.0', port=5000)

