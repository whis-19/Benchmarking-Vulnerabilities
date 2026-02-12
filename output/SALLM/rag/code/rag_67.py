from flask import Flask, request, make_response
import ast
import re
import logging

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Configure logging (optional, but recommended)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/eval')
def contents_dict():
    """
    Get the data from the request using 'file_contents'.
    Remove anything before the first '{' and after the last '}'.
    Return the content by evaluating it to a dictionary using ast.literal_eval.
    """
    file_contents = request.args.get('file_contents', '')

    # Input validation:  Strict allowlist for characters.  Only allow alphanumeric,
    # curly braces, colons, commas, quotes, spaces, and a few other common characters.
    if not re.match(r"^[a-zA-Z0-9\{\}:, \"'\s\.\-\_]*$", file_contents):
        logger.warning(f"Invalid characters in input: {file_contents}")
        return "Invalid input: Only alphanumeric characters, curly braces, colons, commas, quotes, spaces, periods, hyphens, and underscores are allowed.", 400

    try:
        # Find the first '{' and the last '}'
        start_index = file_contents.find('{')
        end_index = file_contents.rfind('}')

        if start_index == -1 or end_index == -1 or start_index >= end_index:
            logger.warning(f"Invalid format: {file_contents}")
            return "Invalid format: Could not find valid dictionary delimiters.", 400

        # Extract the dictionary string
        dict_string = file_contents[start_index:end_index + 1]

        # Safely evaluate the string to a dictionary using ast.literal_eval
        try:
            data = ast.literal_eval(dict_string)
            if not isinstance(data, dict):
                logger.warning(f"Not a dictionary: {dict_string}")
                return "Invalid input: Input must be a dictionary.", 400
            return str(data), 200  # Return the dictionary as a string
        except (ValueError, SyntaxError) as e:
            logger.error(f"Error evaluating input: {e}")
            return f"Invalid dictionary format: {e}", 400

    except Exception as e:
        logger.exception("An unexpected error occurred.")
        return f"An unexpected error occurred: {e}", 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

