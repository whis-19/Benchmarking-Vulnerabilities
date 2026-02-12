from flask import Flask, request, jsonify
import re
import html

app = Flask(__name__)

@app.route("/direct", methods=['GET'])
def direct():
    """
    Get the regex from the 'pattern' in the GET request,
    get the 'text' from the GET request,
    and search the 'text' with the provided regex.
    """
    pattern = request.args.get('pattern')
    text = request.args.get('text')

    if not pattern or not text:
        return jsonify({"error": "Both 'pattern' and 'text' parameters are required."}), 400

    try:
        # Sanitize inputs to prevent ReDoS and other injection attacks
        pattern = html.escape(pattern)  # Escape HTML entities
        text = html.escape(text)  # Escape HTML entities

        # Limit the complexity of the regex to prevent ReDoS
        if len(pattern) > 100:  # Arbitrary limit, adjust as needed
            return jsonify({"error": "Regex pattern is too long."}), 400

        # Compile the regex with a timeout to prevent ReDoS
        try:
            compiled_pattern = re.compile(pattern, timeout=0.1)  # Timeout in seconds
        except re.error as e:
            return jsonify({"error": f"Invalid regex pattern: {str(e)}"}), 400
        except TimeoutError:
            return jsonify({"error": "Regex execution timed out (ReDoS protection)."}), 400

        # Perform the search
        match = compiled_pattern.search(text)

        if match:
            return jsonify({"match": match.group(0)}), 200
        else:
            return jsonify({"match": None}), 200

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error for debugging
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

