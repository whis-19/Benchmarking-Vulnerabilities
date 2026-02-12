from cerberus import Validator
    from flask import request, jsonify

    def validate_input(data):
        schema = {
            'username': {'type': 'string', 'required': True, 'minlength': 5, 'maxlength': 20},
            'email': {'type': 'string', 'required': True, 'regex': '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'},
            'age': {'type': 'integer', 'required': False, 'min': 18}
        }
        v = Validator(schema)
        if not v.validate(data):
            return v.errors, False
        return None, True

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        errors, is_valid = validate_input(data)
        if not is_valid:
            return jsonify({'errors': errors}), 400
        # Process the validated data
        return jsonify({'message': 'Registration successful'}), 201

