import marshal
from flask import Flask, request, abort, Response
import hashlib
import hmac
import secrets
import os

app = Flask(__name__)

# Secret key for HMAC - should be securely generated and stored
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))  # Use environment variable for production
app.config['SECRET_KEY'] = SECRET_KEY

# Allowed classes for unmarshalling.  Crucially important!
ALLOWED_CLASSES = {bytes, str, int, float, list, dict, tuple, set, frozenset}  # Example: Allow only basic types

def is_safe_unmarshal(data):
    """
    Rudimentary check to prevent arbitrary code execution.  This is NOT foolproof.
    This function checks if the unmarshalled data contains only allowed types.
    This is a basic example and might need to be adapted based on your specific needs.
    """
    if isinstance(data, (bytes, str, int, float)):
        return True
    elif isinstance(data, (list, tuple, set, frozenset)):
        for item in data:
            if not is_safe_unmarshal(item):
                return False
        return True
    elif isinstance(data, dict):
        for key, value in data.items():
            if not (isinstance(key, (str, int)) and is_safe_unmarshal(value)):
                return False
        return True
    else:
        return False  # Disallow other types

def verify_hmac(data, received_hmac):
    """Verifies the HMAC of the data."""
    calculated_hmac = hmac.new(
        app.config['SECRET_KEY'].encode('utf-8'),
        data,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(calculated_hmac, received_hmac)


@app.route('/unmarshal', methods=['POST'])
def unmarshal_data():
    """
    Get the marshalled data from the request using 'data' as the key.
    Unmarshal the data, verifying HMAC and allowed types.
    Return the unmarshalled data.
    """
    if request.method == 'POST':
        data = request.form.get('data')
        received_hmac = request.form.get('hmac')

        if not data or not received_hmac:
            return "Missing data or HMAC", 400

        try:
            byte_data = bytes.fromhex(data)
        except ValueError:
            return "Invalid hex data", 400

        # Verify HMAC before unmarshalling
        if not verify_hmac(byte_data, received_hmac):
            return "HMAC verification failed", 400

        try:
            unmarshalled_data = marshal.loads(byte_data)
        except Exception as e:
            print(f"Unmarshal error: {e}")  # Log the error
            return "Unmarshal failed", 400

        # Validate the unmarshalled data to prevent arbitrary code execution
        if not is_safe_unmarshal(unmarshalled_data):
            return "Unsafe data type detected", 400

        return str(unmarshalled_data), 200
    else:
        abort(405)  # Method Not Allowed


@app.route('/generate_data', methods=['GET'])
def generate_data():
    """
    Generates marshalled data and its HMAC for testing purposes.
    This should NOT be exposed in a production environment.
    """
    test_data = {"message": "Hello, world!", "number": 123}  # Example data
    marshalled_data = marshal.dumps(test_data)
    hmac_value = hmac.new(
        app.config['SECRET_KEY'].encode('utf-8'),
        marshalled_data,
        hashlib.sha256
    ).hexdigest()

    hex_data = marshalled_data.hex()

    return f"Marshalled Data (Hex): {hex_data}<br>HMAC: {hmac_value}"


if __name__ == '__main__':
    # NEVER use debug=True in production!
    app.run(debug=True, host='0.0.0.0')

