import pickle
import json
import ast

from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)
app.debug = False  # Disable debugging mode in production

@app.route('/safe_data', methods=['POST'])
def safe_data():
    """
    Receives data as JSON, validates it, and returns it.  Avoids pickle entirely.
    """
    try:
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify({"error": "Data must be a JSON object"}), 400

        # Sanitize and validate data here.  This is crucial.
        # Example:  Check data types, allowed values, etc.
        # For instance, if you expect an integer:
        # if not isinstance(data.get('age'), int):
        #     return jsonify({"error": "Age must be an integer"}), 400

        # Return the data (or a processed version of it)
        return jsonify(data), 200

    except Exception as e:
        print(f"Error processing data: {e}")  # Log the error
        return jsonify({"error": "Invalid JSON data"}), 400


@app.route('/url_check', methods=['GET'])
def url_check():
    """
    Safely parses and validates a URL.
    """
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    try:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return jsonify({"error": "Invalid URL format"}), 400

        # Example: Check if the hostname is allowed
        allowed_hosts = ["example.com", "safe-domain.net"]
        if parsed_url.netloc not in allowed_hosts:
            return jsonify({"error": "Disallowed hostname"}), 403

        # Further validation and sanitization of the URL components can be added here.

        return jsonify({"parsed_url": {
            "scheme": parsed_url.scheme,
            "netloc": parsed_url.netloc,
            "path": parsed_url.path,
            "params": parsed_url.params,
            "query": parsed_url.query,
            "fragment": parsed_url.fragment
        }}), 200

    except Exception as e:
        print(f"Error parsing URL: {e}")
        return jsonify({"error": "Invalid URL"}), 400


@app.route('/safe_eval', methods=['POST'])
def safe_eval():
    """
    Safely evaluates a simple expression using ast.literal_eval.
    """
    try:
        expression = request.get_json().get('expression')
        if not expression:
            return jsonify({"error": "Expression is required"}), 400

        # Use ast.literal_eval to safely evaluate simple expressions
        # This only supports literals (strings, numbers, booleans, lists, dicts, tuples, None)
        result = ast.literal_eval(expression)
        return jsonify({"result": result}), 200

    except (ValueError, SyntaxError) as e:
        print(f"Error evaluating expression: {e}")
        return jsonify({"error": "Invalid expression"}), 400
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

