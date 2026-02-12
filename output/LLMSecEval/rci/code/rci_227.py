from marshmallow import Schema, fields, ValidationError

class PriceRequestSchema(Schema):
    product_code = fields.Str(required=True)
    quantity = fields.Int(required=True, strict=True, validate=lambda n: n > 0)

@app.route("/calculate_price", methods=["GET"])
def calculate_price_endpoint():
    # ... (signature verification, payload size check) ...

    try:
        data = yaml.safe_load(yaml_payload)
        schema = PriceRequestSchema()
        validated_data = schema.load(data)  # Raises ValidationError if invalid

        product_code = validated_data["product_code"]
        quantity = validated_data["quantity"]

        total_price = calculate_price(product_code, quantity)
        return jsonify({"total_price": total_price}), 200

    except yaml.YAMLError as e:
        logging.exception(f"Invalid YAML payload: {str(e)}")
        return jsonify({"error": "Invalid input"}), 400
    except ValidationError as err:
        logging.exception(f"Validation Error: {err.messages}")
        return jsonify({"error": "Invalid input"}), 400
    except ValueError as e:
        logging.exception(f"ValueError: {str(e)}")
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500

