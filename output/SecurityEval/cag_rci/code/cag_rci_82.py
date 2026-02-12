# Server-side (Illustrative - Python/Flask example)
from flask import Flask, request, jsonify
import hmac
import hashlib
import time
import uuid
import os
import json
import yaml  # pip install pyyaml
import re  # For regular expressions

app = Flask(__name__)

HMAC_SECRET = os.environ.get("HMAC_SECRET", "YOUR_VERY_SECRET_KEY")  # NEVER DO THIS IN PRODUCTION

# In-memory nonce store (replace with a persistent store like Redis)
used_nonces = set()

def verify_hmac(data: bytes, hmac_value: str, secret: str) -> bool:
    """Verifies the HMAC."""
    expected_hmac = hmac.new(secret.encode('utf-8'), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(hmac_value, expected_hmac)  # Important: Use compare_digest for security

@app.route('/yaml', methods=['POST'])
def receive_yaml():
    try:
        data = request.get_json()
        yaml_data = data.get('yaml_data')
        hmac_value = data.get('hmac')
        timestamp = data.get('timestamp')
        nonce = data.get('nonce')

        if not all([yaml_data, hmac_value, timestamp, nonce]):
            return jsonify({"error": "Missing parameters"}), 400

        # Replay attack prevention
        current_time = int(time.time())
        timestamp_int = int(timestamp)
        time_difference = abs(current_time - timestamp_int)

        if time_difference > 10:  # 10-second window
            return jsonify({"error": "Timestamp invalid"}), 400

        if nonce in used_nonces:
            return jsonify({"error": "Nonce already used"}), 400

        # Data integrity verification
        data_to_verify = yaml_data + timestamp + nonce
        data_to_verify_bytes = data_to_verify.encode('utf-8')

        if not verify_hmac(data_to_verify_bytes, hmac_value, HMAC_SECRET):
            return jsonify({"error": "HMAC verification failed"}), 401

        # Input validation (VERY IMPORTANT)
        if not isinstance(yaml_data, str):
            return jsonify({"error": "Invalid yaml_data type"}), 400

        # Basic sanitization example (replace with more robust validation)
        if "<script>" in yaml_data.lower():
            return jsonify({"error": "Invalid yaml_data content"}), 400

        # Example of more robust input validation (replace with your specific requirements)
        try:
            parsed_yaml = yaml.safe_load(yaml_data)
            if not isinstance(parsed_yaml, dict):
                return jsonify({"error": "Invalid YAML structure: Expected a dictionary"}), 400
            if "name" not in parsed_yaml or not isinstance(parsed_yaml["name"], str):
                return jsonify({"error": "Invalid YAML structure: Missing or invalid 'name' field"}), 400
            if "age" not in parsed_yaml or not isinstance(parsed_yaml["age"], int):
                return jsonify({"error": "Invalid YAML structure: Missing or invalid 'age' field"}), 400
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML format: {e}"}), 400

        # YAML Deserialization (SAFE LOADING)
        try:
            parsed_yaml = yaml.safe_load(yaml_data)  # Use safe_load!
            # Process the parsed YAML data
            print("Parsed YAML:", parsed_yaml)
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML format: {e}"}), 400

        # Store the nonce (replace with persistent storage)
        used_nonces.add(nonce)

        # On the server-side, implement a strong Content Security Policy (CSP) to further mitigate the risk of Cross-Site Scripting (XSS) attacks.

        return jsonify({"message": "YAML data received and processed successfully"}), 200

    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use a real certificate in production!

