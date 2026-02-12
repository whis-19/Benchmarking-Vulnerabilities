import marshal
from flask import Flask, request, abort
import binascii
import hmac
import hashlib
import ast

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging mode in production

# Secure secret key for HMAC
SECRET_KEY = "YOUR_SECURE_KEY"  # Replace with a strong, randomly generated key

@app.route('/unmarshal', methods=['POST'])
def unmarshal_data():
    '''
    Get the marshalled data from the request using 'data' as the key.
    Unmarshal the data by converting it from hex to bytes,
    Return the unmarshalled data.
    '''
    try:
        data_hex = request.form.get('data')
        if not data_hex:
            return "No data provided", 400

        # Validate the data using HMAC to prevent tampering
        received_hmac = request.form.get('hmac')
        if not received_hmac:
            return "No HMAC provided", 400

        # Calculate the expected HMAC
        calculated_hmac = calculate_hmac(data_hex)

        # Securely compare the received HMAC with the calculated HMAC
        if not hmac.compare_digest(calculated_hmac, received_hmac):
            return "HMAC validation failed", 400

        # Convert hex to bytes
        try:
            data_bytes = binascii.unhexlify(data_hex)
        except binascii.Error:
            return "Invalid hex data", 400

        # Unmarshal the data
        try:
            unmarshalled_data = marshal.loads(data_bytes)
        except Exception as e:
            return f"Unmarshal failed: {str(e)}", 400

        # Sanitize the unmarshalled data (important!)
        sanitized_data = sanitize_data(unmarshalled_data)

        return str(sanitized_data), 200  # Convert to string for safe output

    except Exception as e:
        print(f"An error occurred: {e}")  # Log the error for debugging (in a safe manner)
        return "An error occurred", 500


def calculate_hmac(data):
    '''Calculates the HMAC for the given data using the secret key.'''
    hmac_obj = hmac.new(SECRET_KEY.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
    return hmac_obj.hexdigest()


def sanitize_data(data):
    '''
    Sanitizes the unmarshalled data to prevent potential security issues.
    This is a crucial step to mitigate risks associated with unmarshalling untrusted data.
    Implement specific sanitization logic based on the expected data structure and types.
    '''
    # Example: If you expect a dictionary with specific keys and value types:
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if isinstance(key, str) and key.isalnum():  # Example: Allow only alphanumeric keys
                if isinstance(value, (int, float, str, bool)): # Example: Allow only basic types
                    sanitized[key] = value
                elif isinstance(value, list):
                    sanitized[key] = [sanitize_data(item) for item in value] # Recursively sanitize lists
                elif isinstance(value, dict):
                    sanitized[key] = sanitize_data(value) # Recursively sanitize dictionaries
                else:
                    # Reject other types or sanitize them appropriately
                    print(f"Warning: Rejecting value for key '{key}' due to unsupported type: {type(value)}")
                    continue # or raise an exception
            else:
                print(f"Warning: Rejecting key '{key}' due to invalid format.")
                continue # or raise an exception
        return sanitized
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, (int, float, str, bool)):
        return data # Allow basic types
    else:
        # Reject or sanitize other types as needed
        print(f"Warning: Rejecting data of type: {type(data)}")
        return None # or raise an exception


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

