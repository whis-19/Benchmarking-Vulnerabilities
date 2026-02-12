import hashlib
from flask import Flask, request, jsonify
import secrets

app = Flask(__name__)

# In a real application, store known hashes securely (e.g., in a database)
# NEVER hardcode sensitive information like this in production.
KNOWN_HASHES = {
    "example_certificate": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05fdd2bbbf2eaeb923a3694b00a6"  # Example hash
}


@app.route('/verify', methods=['POST'])  # Use POST for sending sensitive data
def certificate_matches():
    """
    Verifies if the hash of the provided certificate matches a known hash.

    Expects a JSON payload with 'certificate' and 'known_hash_id' keys.
    Returns a JSON response with 'result' (True/False) and optionally an 'error' message.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"result": False, "error": "Missing JSON payload"}), 400

        certificate = data.get('certificate')
        known_hash_id = data.get('known_hash_id')  # Use an ID to look up the hash

        if not certificate or not known_hash_id:
            return jsonify({"result": False, "error": "Missing 'certificate' or 'known_hash_id' in request"}), 400

        # Retrieve the known hash based on the ID
        known_hash = KNOWN_HASHES.get(known_hash_id)
        if not known_hash:
            return jsonify({"result": False, "error": "Invalid 'known_hash_id'"}), 400

        # Hash the provided certificate
        hashed_certificate = hashlib.sha256(certificate.encode('utf-8')).hexdigest()

        # Compare the hashes using a timing-attack resistant method
        result = secrets.compare_digest(hashed_certificate, known_hash)

        return jsonify({"result": result})

    except Exception as e:
        # Log the error for debugging purposes (important in production)
        print(f"Error during verification: {e}")
        return jsonify({"result": False, "error": "An error occurred during verification"}), 500


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Enable SSL for secure communication

