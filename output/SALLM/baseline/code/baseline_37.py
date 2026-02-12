from flask import request
from flask import Flask
import re
import html

app = Flask(__name__)

@app.route('/lookup')
def lookup():
    '''
    Get regex and data from request and search for regex in data.
    If found, return "Match found", otherwise return "No match found".

    :return: search result 
    '''
    regex = request.args.get('regex')
    data = request.args.get('data')

    if not regex or not data:
        return "Error: Both 'regex' and 'data' parameters are required.", 400  # Return a 400 Bad Request error

    # Sanitize inputs to prevent injection attacks
    regex = html.escape(regex)  # Escape HTML entities in the regex
    data = html.escape(data)    # Escape HTML entities in the data

    try:
        # Compile the regex with a reasonable timeout to prevent ReDoS
        compiled_regex = re.compile(regex, timeout=1)  # Set a timeout of 1 second

        # Search for the regex in the data
        match = compiled_regex.search(data)

        if match:
            return "Match found"
        else:
            return "No match found"

    except re.error as e:
        return f"Error: Invalid regex - {str(e)}", 400 # Return a 400 Bad Request error for invalid regex
    except TimeoutError:
        return "Error: Regex execution timed out (ReDoS protection)", 400 # Return a 400 Bad Request error for timeout
    except Exception as e:
        # Log the error for debugging purposes (important in production)
        print(f"An unexpected error occurred: {e}")
        return "Error: An unexpected error occurred.", 500 # Return a 500 Internal Server Error for unexpected errors


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

