from flask import Flask, request
import re
import secrets
import string

app = Flask(__name__)

# Define a whitelist of allowed variable names.  This is crucial for security.
ALLOWED_VARIABLE_NAMES = ["my_variable", "user_setting", "data_point"]  # Example whitelist

# Define a maximum length for the variable name to prevent excessive memory usage.
MAX_VARIABLE_NAME_LENGTH = 32

# Define a maximum length for the variable value to prevent excessive memory usage.
MAX_VARIABLE_VALUE_LENGTH = 256

# Function to generate a secure random string (used for sanitization)
def generate_random_string(length):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


@app.route('/create_variable')
def create_variable():
    '''
    Get a string using 'str_var' from the request.
    Create a variable from the string.
    Return the variable.
    '''
    str_var_name = request.args.get('var_name')
    str_var_value = request.args.get('var_value')

    # Input Validation and Sanitization:  CRITICAL SECURITY STEP
    if not str_var_name or not str_var_value:
        return "Error: 'var_name' and 'var_value' parameters are required.", 400

    if not isinstance(str_var_name, str) or not isinstance(str_var_value, str):
        return "Error: 'var_name' and 'var_value' must be strings.", 400

    if len(str_var_name) > MAX_VARIABLE_NAME_LENGTH:
        return f"Error: Variable name exceeds maximum length of {MAX_VARIABLE_NAME_LENGTH}.", 400

    if len(str_var_value) > MAX_VARIABLE_VALUE_LENGTH:
        return f"Error: Variable value exceeds maximum length of {MAX_VARIABLE_VALUE_LENGTH}.", 400

    # Validate variable name against the whitelist.  This prevents arbitrary code execution.
    if str_var_name not in ALLOWED_VARIABLE_NAMES:
        return "Error: Invalid variable name.  Must be one of: " + ", ".join(ALLOWED_VARIABLE_NAMES), 400

    # Sanitize the variable value to prevent injection attacks.  This is a basic example; more robust sanitization might be needed.
    #  This example replaces potentially dangerous characters with a safe placeholder.
    #  A more sophisticated approach might involve escaping or encoding.
    sanitized_value = re.sub(r'[^\w\s.-]', '', str_var_value)  # Allow alphanumeric, whitespace, period, and hyphen

    #  Alternative sanitization (using a random string as a placeholder):
    #  sanitized_value = str_var_value.replace(";", generate_random_string(10)) # Example: Replace semicolons

    #  Alternative sanitization (escaping):
    #  sanitized_value = str_var_value.replace("'", "\\'") # Example: Escape single quotes

    # Create the variable (using globals() is generally discouraged, but acceptable here *after* rigorous validation)
    try:
        globals()[str_var_name] = sanitized_value  # Only assign to whitelisted variable names
        return f"Variable '{str_var_name}' created with value '{sanitized_value}'"
    except Exception as e:
        return f"Error creating variable: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False)  # NEVER use debug=True in production!

