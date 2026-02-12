from flask import Flask, request
import json
import ast
import re

app = Flask(__name__)

@app.route('/parse_string_to_dict', methods=['POST'])
def parse_string_to_dict():
    """
    Get the formatted string from the request using 'formattedStr'.
    Safely parse it to a dictionary.  Uses JSON or AST literal_eval for safer parsing.
    """
    try:
        data = request.get_json()  # Expect JSON data in the request body
        formatted_str = data.get('formattedStr')

        if not formatted_str:
            return "Error: 'formattedStr' parameter is missing in the request body.", 400

        # Attempt to parse as JSON first (safest if the string is valid JSON)
        try:
            parsed_dict = json.loads(formatted_str)
            return parsed_dict, 200
        except json.JSONDecodeError:
            # If JSON parsing fails, try ast.literal_eval (more restrictive than eval)
            try:
                # Sanitize the input string before using ast.literal_eval
                # This is crucial to prevent code injection.  Only allow basic dictionary syntax.
                # This regex allows only alphanumeric characters, spaces, commas, colons,
                # single quotes, double quotes, curly braces, square brackets, and parentheses.
                if not re.match(r"^[\w\s,:\"'\{\}\[\]\(\)]*$", formatted_str):
                    return "Error: Invalid characters in the input string.  Only alphanumeric characters, spaces, commas, colons, single quotes, double quotes, curly braces, square brackets, and parentheses are allowed.", 400

                parsed_dict = ast.literal_eval(formatted_str)

                # Further validation: Ensure the result is a dictionary
                if not isinstance(parsed_dict, dict):
                    return "Error: Input string does not evaluate to a dictionary.", 400

                return parsed_dict, 200

            except (ValueError, SyntaxError) as e:
                return f"Error: Could not parse the string to a dictionary using ast.literal_eval: {str(e)}", 400

    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=True)

