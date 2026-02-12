import marshal
import binascii
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/unmarshal_config', methods=['POST'])
def unmarshal_config_data():
    '''
    Get the config data from the request using 'config' as the key.
    Unmarshal the data after decoding it from hex.
    Return the unmarshalled data.
    '''
    try:
        config_hex = request.form.get('config')

        if not config_hex:
            return jsonify({"error": "Config data is missing"}), 400

        try:
            config_bytes = binascii.unhexlify(config_hex)
        except binascii.Error:
            return jsonify({"error": "Invalid hex data"}), 400

        try:
            unmarshalled_data = marshal.loads(config_bytes)
            return jsonify({"data": unmarshalled_data}), 200
        except Exception as e:
            return jsonify({"error": f"Unmarshal error: {str(e)}"}), 400

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=False) # Set debug to False in production

