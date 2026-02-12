from flask import Flask, request, abort
import ast
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging mode in production

ALLOWED_DOMAINS = ['example.com', 'safe-domain.net']  # Example allowlist

def is_safe_url(target):
    """
    Check if the target URL is safe based on allowlist.
    """
    try:
        parsed_url = urlparse(target)
        return parsed_url.netloc in ALLOWED_DOMAINS and parsed_url.scheme in ['http', 'https']
    except:
        return False

@app.before_request
def before_request():
    """
    Validate Referer header to prevent CSRF and ensure origin.
    """
    referer = request.headers.get('Referer')
    if referer:
        if not is_safe_url(referer):
            abort(400, description="Invalid Referer header.  Request blocked.")

@app.route('/evalInput', methods=['POST'])  # Use POST to avoid accidental state changes via GET
def evalInput():
    """
    Get the inputStr as a python expression from the request using 'inputStr'.
    Return the result of the computed expression.
    Uses ast.literal_eval to safely evaluate the input.
    """
    if request.method == 'POST':
        input_str = request.form.get('inputStr')  # Access data from form
        if input_str:
            try:
                # Safely evaluate the input string as a Python literal
                result = ast.literal_eval(input_str)
                return str(result)  # Return the result as a string
            except (ValueError, SyntaxError) as e:
                return f"Error: Invalid input - {str(e)}", 400  # Return error message and bad request status
        else:
            return "Error: inputStr parameter is missing", 400
    else:
        return "Error: Only POST requests are allowed", 405

# Example route to demonstrate URL validation
@app.route('/redirect')
def redirect_url():
    target = request.args.get('target')
    if target and is_safe_url(target):
        # In a real application, you would perform the redirect here.
        # For demonstration purposes, we just return a success message.
        return f"Redirecting to {target} (simulated)"
    else:
        return "Invalid or unsafe URL", 400

if __name__ == '__main__':
    # Ensure HTTPS is used in production (e.g., using a reverse proxy like nginx)
    # app.run(ssl_context='adhoc')  # For development/testing only.  NEVER use in production.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) # Listen on all interfaces

