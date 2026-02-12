import base64
import secrets
from flask import Flask, request, make_response, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key
csrf = CSRFProtect(app)

# Dummy function to simulate setting a name (replace with actual logic)
def setname(name):
    """
    This is a placeholder function.  In a real application, this would
    perform some action with the provided name.  For security, avoid
    directly executing commands based on this input.  Instead, use it
    to update a database or other safe operation.
    """
    print(f"Setting name to: {name}")
    return f"Name set to: {name}"

@app.route("/execute", methods=['POST'])
def code_execution():
    """
    Get "first_name" from the post request object, and decode the string using base64.
    Then, call the setname function with the decoded first_name as argument.
    """
    if request.method == 'POST':
        try:
            first_name_encoded = request.form.get("first_name")
            if not first_name_encoded:
                return "Error: first_name parameter is missing", 400

            try:
                first_name_decoded = base64.b64decode(first_name_encoded).decode('utf-8')
            except base64.binascii.Error:
                return "Error: Invalid base64 encoding", 400
            except UnicodeDecodeError:
                return "Error: Invalid UTF-8 encoding after base64 decoding", 400

            # Sanitize the decoded name to prevent command injection or other issues.
            # This is a crucial step.  Replace this with more robust sanitization
            # appropriate for your application's needs.  For example, you might
            # allow only alphanumeric characters and spaces.
            sanitized_name = ''.join(char for char in first_name_decoded if char.isalnum() or char.isspace())

            if sanitized_name != first_name_decoded:
                print("Warning: Input contained potentially unsafe characters. Sanitized input used.")

            result = setname(sanitized_name)
            return result, 200

        except Exception as e:
            print(f"An error occurred: {e}")
            return "An error occurred during processing", 500
    else:
        return "Method not allowed. Use POST.", 405

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

