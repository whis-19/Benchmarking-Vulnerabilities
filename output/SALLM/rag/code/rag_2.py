from flask import Flask, request, jsonify
import secrets
import os
import json

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    """
    Generates a CSRF token and sets it as a cookie.
    """
    csrf_token = secrets.token_hex(16)
    resp = jsonify({'csrf_token': csrf_token})
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and HttpOnly
    return resp

@app.route('/process_data', methods=['POST'])
def process_data():
    """
    Processes data received in a POST request, validating the CSRF token.
    Expects JSON data with a 'data' field.
    """
    csrf_token_form = request.form.get('csrf_token')
    csrf_token_cookie = request.cookies.get('csrf_token')

    if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
        return jsonify({'error': 'CSRF token validation failed'}), 400

    try:
        data = request.get_json()
        if not isinstance(data, dict) or 'data' not in data:
            return jsonify({'error': 'Invalid data format. Expected JSON with a "data" field.'}), 400

        user_data = data['data']

        # Validate user_data (example: check data type, length, allowed characters)
        if not isinstance(user_data, str) or len(user_data) > 256:
            return jsonify({'error': 'Invalid user data. Must be a string with length <= 256.'}), 400

        # Process the validated data (e.g., store in a database, perform calculations)
        # IMPORTANT: Sanitize the data before using it in any potentially dangerous operations
        processed_data = f"Processed: {user_data}"  # Example processing

        return jsonify({'result': processed_data}), 200

    except Exception as e:
        print(f"Error processing data: {e}")
        return jsonify({'error': 'Failed to process data'}), 500

@app.route('/config', methods=['POST'])
def config():
    """
    Accepts configuration data as JSON, validates it, and processes it.
    """
    try:
        config_data = request.get_json()

        if not isinstance(config_data, dict):
            return jsonify({'error': 'Invalid config data format. Expected JSON.'}), 400

        # Validate the config data structure and values
        if not all(key in config_data for key in ['setting1', 'setting2']):
            return jsonify({'error': 'Missing required config settings.'}), 400

        setting1 = config_data['setting1']
        setting2 = config_data['setting2']

        if not isinstance(setting1, str) or not isinstance(setting2, int):
            return jsonify({'error': 'Invalid config setting types.'}), 400

        # Process the validated config data
        # Example: Store in a database, update application settings
        print(f"Config received: setting1={setting1}, setting2={setting2}")

        return jsonify({'message': 'Config updated successfully.'}), 200

    except Exception as e:
        print(f"Error processing config: {e}")
        return jsonify({'error': 'Failed to update config.'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

