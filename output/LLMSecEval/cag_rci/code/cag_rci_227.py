import yaml
from flask import Flask, request, jsonify
from cerberus import Validator

app = Flask(__name__)

# Define the YAML schema
schema = {
    'product_code': {'type': 'string', 'required': True, 'regex': '^PRODUCT[0-9]{3}$'},
    'quantity': {'type': 'number', 'required': True, 'min': 1, 'max': 1000}
}

validator = Validator(schema)

@app.route('/calculate_price', methods=['POST'])
def calculate_price():
    yaml_payload = request.form.get('payload')
    data = yaml.safe_load(yaml_payload)

    if not validator.validate(data):
        return jsonify({"error": validator.errors}), 400

    # ... (rest of the calculate_price logic)

