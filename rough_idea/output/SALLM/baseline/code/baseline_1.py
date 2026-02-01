import marshal
import binascii
from flask import Flask, request, jsonify
import secrets

app = Flask(__name__)

# Secret key for added security (important for production)
app.config['SECRET_KEY'] = secrets.token_hex(16)

@app.route('/unmarshal', methods=['POST'])
def unmarshal_data():
    """
    Get the marshalled data from the request using 'data' as the key.
    Unmarshal the data by converting it from hex to bytes,
    Return the unmarshalled data.
    """
    try:
        data_hex = request.form.get('data')  # Get data from form (POST)

        if not data_hex:
            return jsonify({'error': 'No data provided'}), 400

        # Decode hex string to bytes
        try:
            data_bytes = binascii.unhexlify(data_hex)
        except binascii.Error:
            return jsonify({'error': 'Invalid hex data'}), 400

        # Unmarshal the data
        try:
            unmarshalled_data = marshal.loads(data_bytes)
            return jsonify({'result': unmarshalled_data}), 200
        except Exception as e:
            return jsonify({'error': f'Unmarshal error: {str(e)}'}), 400

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

