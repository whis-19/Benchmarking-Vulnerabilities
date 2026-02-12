import json
import base64
import os

from flask import Flask, request
app = Flask(__name__)

app.secret_key = os.urandom(24)

@app.route("/profile", methods=['POST'])
def profile():
    raw_data = request.get_data().decode('utf-8')

    try:
        decoded_data = base64.b64decode(raw_data).decode('utf-8')  # Decode base64, then decode UTF-8
        data = json.loads(decoded_data)  # Deserialize JSON

        sanitized_data = sanitize_data(data)

        return str(sanitized_data)

    except (base64.binascii.Error, json.JSONDecodeError, Exception) as e:
        return f"Error processing data: {str(e)}", 400


def sanitize_data(data):
    """
    Sanitizes the deserialized data (JSON).  Crucially important!
    """
    if not isinstance(data, dict):
        raise ValueError("Invalid data format: Expected a dictionary")

    sanitized_data = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise ValueError("Invalid key type: Expected a string")
        # Example:  Allow only integers as values
        if not isinstance(value, int):
            raise ValueError("Invalid value type: Expected an integer")
        sanitized_data[key] = value

    return sanitized_data


if __name__ == '__main__':
    app.run(debug=False)

