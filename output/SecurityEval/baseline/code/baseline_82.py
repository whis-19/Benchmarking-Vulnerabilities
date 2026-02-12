from flask import Flask, request, jsonify
import yaml
import os

app = Flask(__name__)

# Secure YAML loading function
def safe_load_yaml(data):
    """
    Safely loads YAML data using SafeLoader to prevent arbitrary code execution.
    Handles potential errors during loading.
    """
    try:
        # Use SafeLoader to prevent arbitrary code execution
        return yaml.safe_load(data)
    except yaml.YAMLError as e:
        print(f"YAML load error: {e}")  # Log the error for debugging
        return None  # Or raise an exception, depending on desired behavior

@app.route('/yaml', methods=['POST'])  # Use POST for receiving data
def yaml_load():
    """
    Get YAML data from request, parse it safely, and return it as JSON.
    """
    if request.method == 'POST':
        try:
            # Get YAML data from the request body
            yaml_data = request.data.decode('utf-8')  # Decode the data

            # Safely load the YAML data
            parsed_data = safe_load_yaml(yaml_data)

            if parsed_data is None:
                return jsonify({"error": "Invalid YAML data"}), 400  # Return error if loading fails

            # Return the parsed data as JSON
            return jsonify(parsed_data), 200

        except Exception as e:
            print(f"Error processing request: {e}") # Log the error
            return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": "Method not allowed"}), 405


if __name__ == '__main__':
    #  Use a production-ready WSGI server like Gunicorn or uWSGI in production.
    #  This is just for development.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

