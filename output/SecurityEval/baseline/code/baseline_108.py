from flask import Flask, request, jsonify
import re
import html

app = Flask(__name__)

@app.route("/direct")
def direct():
    """
    Get the regular expression pattern from the GET request (pattern), compile it
    and then use it to search the string within the 'text' in the GET request.
    """
    pattern = request.args.get("pattern")
    text = request.args.get("text")

    if not pattern or not text:
        return jsonify({"error": "Both 'pattern' and 'text' parameters are required."}), 400

    try:
        # Sanitize the pattern to prevent ReDoS attacks.  Limit the length and complexity.
        if len(pattern) > 100:
            return jsonify({"error": "Pattern is too long.  Maximum length is 100 characters."}), 400

        # Basic character whitelist.  Allows alphanumeric, spaces, and common regex metacharacters.
        #  This is a starting point and may need adjustment based on the specific use case.
        if not re.match(r"^[\w\s\.\*\+\?\[\]\(\)\{\}\|\^\$\\]*$", pattern):
            return jsonify({"error": "Pattern contains disallowed characters.  Allowed characters: alphanumeric, spaces, . * + ? [ ] ( ) { } | ^ $ \\"}), 400

        # Compile the regular expression.  Use re.compile for efficiency if the pattern is reused.
        regex = re.compile(pattern)

        # Sanitize the input text to prevent XSS attacks.
        text = html.escape(text)

        # Perform the search.
        match = regex.search(text)

        if match:
            return jsonify({"match": match.group(0)})
        else:
            return jsonify({"match": None})

    except re.error as e:
        return jsonify({"error": f"Invalid regular expression: {str(e)}"}), 400
    except Exception as e:
        # Log the error for debugging purposes.  Do *not* expose the full error message to the user in production.
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    app.run(debug=True)

