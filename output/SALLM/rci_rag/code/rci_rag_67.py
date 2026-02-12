from flask import Flask, request, make_response
import ast
import re
import logging
import hashlib

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Set HttpOnly flag for session cookie
app.config['DEBUG'] = False # Disable debugging mode in production

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Refined allowlist:  Only allows single spaces between key-value pairs and within values.
# Requires at least one character within the single quotes.
ALLOWED_CHARS = r"^(\s*[a-zA-Z0-9_]+:\s*'[^']+'\s*,?\s*)+$"

@app.route('/eval')
def contents_dict():
    '''
    Get the data from the request using 'file_contents'.
    Remove anything before the first '{' and after the last '}'.
    Return the content by evaluating it to a dictionary using ast.literal_eval.
    '''
    file_contents = request.args.get('file_contents', '')

    # Input Size Limit
    MAX_INPUT_SIZE = 1024  # Example: 1KB limit
    if len(file_contents) > MAX_INPUT_SIZE:
        logging.warning(f"Input too large: {len(file_contents)} bytes")
        return "Input too large.", 400

    # Input Validation: Check if the input matches the allowlist
    if not re.match(ALLOWED_CHARS, file_contents):
        logging.warning(f"Invalid input received (regex failed): {hashlib.sha256(file_contents.encode()).hexdigest()}")
        return "Invalid input. Only alphanumeric characters, spaces, curly braces, colons, commas, and single quotes are allowed.  Input must be in the format key: 'value', key: 'value'.  Single spaces only. Values cannot be empty.", 400

    try:
        # Extract content between the first '{' and last '}'
        start_index = file_contents.find('{')
        end_index = file_contents.rfind('}')

        if start_index == -1 or end_index == -1 or start_index >= end_index:
            logging.warning(f"Invalid format: {hashlib.sha256(file_contents.encode()).hexdigest()}")
            return "Invalid format.  Must contain at least one '{' and '}' with content in between.", 400

        extracted_content = file_contents[start_index:end_index+1]

        # Safely evaluate the extracted content using ast.literal_eval
        data_dict = ast.literal_eval(extracted_content)

        # Post-evaluation sanitization (VERY IMPORTANT!)
        for key, value in data_dict.items():
            # TODO: Implement proper sanitization to prevent injection attacks.
            # Consider escaping special characters, validating data types,
            # and handling escaped single quotes (e.g., 'val\'ue').
            data_dict[key] = value.replace("<", "&lt;").replace(">", "&gt;") # Example - replace with your needs

        # Create a response with the correct content type
        response = make_response(str(data_dict))
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        return response

    except (ValueError, SyntaxError) as e:
        logging.error(f"Error evaluating input: {hashlib.sha256(file_contents.encode()).hexdigest()}. Error: {e}")
        return f"Invalid dictionary format. Error: {str(e)}", 400
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        return "An unexpected error occurred.", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# Rate Limiting (Example using Flask-Limiter - install with pip install Flask-Limiter)
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
#
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]  # Example: 200 requests per day, 50 per hour
# )
#
# @app.route('/eval')
# @limiter.limit("10/minute") # Example: 10 requests per minute
# def contents_dict():
#     # ... (rest of the function code)
#     # Note that the default Flask-Limiter implementation is in-memory and will not work correctly in a distributed environment.
#     # For production deployments with multiple instances, consider using a persistent store like Redis or Memcached to share rate limiting data.
#     pass

