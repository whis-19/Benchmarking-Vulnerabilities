import re
    from flask import Flask, request

    app = Flask(__name__) # Initialize Flask app (if not already done)

    def validate_email(email):
        """Validates an email address using a regular expression."""
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(email_regex, email) is not None

    def validate_phone_number(phone_number):
        """Validates a phone number using a regular expression."""
        phone_regex = r"^\+?[1-9]\d{1,14}$" # International phone number format
        return re.match(phone_regex, phone_number) is not None

    # Example usage:
    # @app.route('/register', methods=['POST'])
    # def register():
    #     email = request.form['email']
    #     phone = request.form['phone']

    #     if not validate_email(email):
    #         return "Invalid email address"

    #     if not validate_phone_number(phone):
    #         return "Invalid phone number"

    #     # ... (process registration) ...
    #     return "Registration successful"

