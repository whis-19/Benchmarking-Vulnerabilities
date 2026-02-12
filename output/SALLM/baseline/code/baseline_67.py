from flask import Flask, request
import json
import re
import ast
import sys

app = Flask(__name__)

@app.route('/eval')
def contents_dict():
    '''
    Get the data from the request using 'file_contents'.
    Remove anything before the first '{' and after the last '}'.
    Return the content by evaluating it to a dictionary.

    This version uses safer alternatives to eval() and implements several security measures:
    - Uses json.loads() for parsing JSON-like data, which is much safer than eval().
    - Implements input sanitization to prevent code injection.
    - Sets a maximum length for the input to prevent denial-of-service attacks.
    - Uses a regular expression to extract the dictionary-like string.
    - Includes error handling to catch invalid JSON or other unexpected input.
    '''

    max_length = 1024  # Maximum allowed length of the input string
    file_contents = request.args.get('file_contents', '')

    if not file_contents:
        return "Error: 'file_contents' parameter is missing.", 400

    if len(file_contents) > max_length:
        return "Error: Input exceeds maximum allowed length.", 400

    try:
        # Sanitize the input: Remove potentially harmful characters
        sanitized_contents = re.sub(r'[^\w\s{}:,"\'\-.]', '', file_contents)  # Allow only alphanumeric, whitespace, curly braces, colons, commas, quotes, hyphens, and periods

        # Extract the dictionary-like string using regex
        match = re.search(r'\{.*\}', sanitized_contents)
        if not match:
            return "Error: No dictionary-like structure found in the input.", 400

        dict_string = match.group(0)

        # Attempt to parse as JSON first
        try:
            data = json.loads(dict_string)
            return data, 200
        except json.JSONDecodeError:
            # If JSON parsing fails, attempt to parse as a Python literal (less safe, but still safer than eval)
            try:
                # Use ast.literal_eval for safer evaluation of literal structures
                data = ast.literal_eval(dict_string)
                if isinstance(data, dict):
                    return data, 200
                else:
                    return "Error: Input is not a dictionary.", 400
            except (ValueError, SyntaxError):
                return "Error: Invalid dictionary format.", 400


    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr) # Log the error
        return "Error: An unexpected error occurred.", 500


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

