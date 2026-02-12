import pickle
import hashlib
import hmac
import secrets
import json

from flask import Flask, request, make_response, abort
from itsdangerous import URLSafeTimedSerializer, BadSignature

app = Flask(__name__)

# Secret key for signing data.  Keep this VERY secret!
SECRET_KEY = secrets.token_hex(32)  # Generate a strong random key
app.config['SECRET_KEY'] = SECRET_KEY

# Allowed classes for deserialization.  Restrict to ONLY what's needed.
ALLOWED_CLASSES = {str, int, float, list, dict, tuple}  # Example: Allow only basic types

# Initialize the serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def is_safe_class(obj):
    """
    Checks if the object's class is in the allowed list.
    """
    return type(obj) in ALLOWED_CLASSES


def verify_signature(data, signature, key):
    """
    Verifies the HMAC signature of the data.
    """
    hmac_obj = hmac.new(key.encode('utf-8'), data, hashlib.sha256)
    return hmac.compare_digest(hmac_obj.hexdigest(), signature)


def serialize_data(data, key):
    """
    Serializes data using pickle and adds an HMAC signature for integrity.
    """
    serialized_data = pickle.dumps(data)
    hmac_obj = hmac.new(key.encode('utf-8'), serialized_data, hashlib.sha256)
    signature = hmac_obj.hexdigest()
    return serialized_data, signature


def deserialize_data(serialized_data, signature, key):
    """
    Deserializes data after verifying its HMAC signature and checking allowed classes.
    """
    try:
        if not verify_signature(serialized_data, signature, key):
            raise ValueError("Invalid signature. Data may be tampered with.")

        # Custom Unpickler to restrict allowed classes
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                # Only allow classes from the __main__ module if they are in ALLOWED_CLASSES
                if module == "__main__" and name in ALLOWED_CLASSES:
                    return getattr(__import__(module), name)
                elif module == "builtins" and name in ALLOWED_CLASSES:
                    return getattr(__import__(module), name)
                raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

        unpickler = RestrictedUnpickler(io.BytesIO(serialized_data))
        data = unpickler.load()

        # Double-check that all objects in the deserialized data are safe
        def check_safe(obj):
            if isinstance(obj, (list, tuple, set)):
                for item in obj:
                    if not is_safe_class(item):
                        return False
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    if not (is_safe_class(key) and is_safe_class(value)):
                        return False
            return is_safe_class(obj)

        if not check_safe(data):
            raise ValueError("Deserialized data contains unsafe classes.")

        return data

    except (ValueError, pickle.UnpicklingError) as e:
        print(f"Deserialization error: {e}")
        return None  # Or raise an exception, depending on desired behavior
import io

@app.route('/unpickled', methods=['POST'])
def unpickled():
    """
    Receives pickled data, verifies its integrity, and deserializes it.
    """
    if request.method == 'POST':
        data = request.form.get('data')
        signature = request.form.get('signature')

        if not data or not signature:
            return "Missing data or signature", 400

        try:
            # Convert hex-encoded data back to bytes
            serialized_data = bytes.fromhex(data)

            # Deserialize the data
            deserialized_data = deserialize_data(serialized_data, signature, app.config['SECRET_KEY'])

            if deserialized_data is None:
                return "Deserialization failed", 400

            return str(deserialized_data)  # Or return as JSON, etc.

        except Exception as e:
            print(f"Error: {e}")
            return "An error occurred", 500


@app.route('/serialized', methods=['POST'])
def serialized():
    """
    Serializes data and returns the serialized data and signature.
    This is just for demonstration and testing.  In a real application,
    you'd likely serialize the data on the server-side and send it to
    another service.
    """
    if request.method == 'POST':
        data_to_serialize = request.form.get('data')

        if not data_to_serialize:
            return "Missing data", 400

        try:
            # Convert the string data to a Python object (e.g., using json.loads)
            data = json.loads(data_to_serialize)

            # Serialize the data and generate the signature
            serialized_data, signature = serialize_data(data, app.config['SECRET_KEY'])

            # Convert the serialized data to a hex string for transmission
            serialized_data_hex = serialized_data.hex()

            return json.dumps({'data': serialized_data_hex, 'signature': signature})

        except json.JSONDecodeError:
            return "Invalid JSON data", 400
        except Exception as e:
            print(f"Error: {e}")
            return "An error occurred", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Demonstrates CSRF protection using a pseudorandom token.
    """
    if request.method == 'GET':
        # Generate a pseudorandom token
        csrf_token = secrets.token_hex(16)

        # Create a response and set the token as a cookie
        resp = make_response('''
            <form method="post">
                CSRF Token: <input type="hidden" name="csrf_token" value="{}" />
                Username: <input type="text" name="username" /><br>
                Password: <input type="password" name="password" /><br>
                <input type="submit" value="Login" />
            </form>
        '''.format(csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')  # Secure cookie
        return resp

    elif request.method == 'POST':
        # Verify the CSRF token
        form_token = request.form.get('csrf_token')
        cookie_token = request.cookies.get('csrf_token')

        if not form_token or not cookie_token or not hmac.compare_digest(form_token, cookie_token):
            abort(400, "CSRF token mismatch")  # Or return an error page

        # Process the login (after CSRF validation)
        username = request.form.get('username')
        password = request.form.get('password')

        # In a real application, you would validate the username and password
        if username == "test" and password == "password":
            return "Login successful!"
        else:
            return "Login failed", 401


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

