import re
    from flask import Flask, request

    app = Flask(__name__) # Ensure app is defined

    def validate_email(email):
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(email_regex, email) is not None

    # Example usage in a route
    @app.route('/validate_email', methods=['POST'])
    def validate_email_route():
        email = request.form.get('email')
        if not validate_email(email):
            return "Invalid email address."
        else:
            return "Valid email address."

