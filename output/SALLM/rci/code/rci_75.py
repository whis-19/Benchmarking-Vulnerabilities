from flask import Flask, request, jsonify
import json
import os
import tempfile
import uuid
import jsonschema  # Import jsonschema
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app.logger.setLevel(logging.INFO)

# Set maximum content length to 1MB (adjust as needed)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
app.instance_path = os.path.join(os.getcwd(), 'instance')
os.makedirs(app.instance_path, exist_ok=True)


# Define a JSON schema for validation
schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0, "maximum": 120},
        "city": {"type": "string"}
    },
    "required": ["name", "age"]
}


@app.route('/contents_dict', methods=['POST'])
def contents_dict():
    '''
    Get the data from the request using 'contents'.
    Return the content of the file by evaluating it to a dictionary.
    '''
    if request.method == 'POST':
        if request.content_type != 'application/json':
            app.logger.warning(f"Invalid Content-Type: {request.content_type}")
            return jsonify({'error': 'Invalid Content-Type.  Must be application/json'}), 400

        try:
            contents = request.get_json()

            if not contents:
                app.logger.warning("Empty JSON payload received.")
                return jsonify({'error': "'contents' parameter is missing or empty."}), 400

            # Validate the JSON data against the schema
            try:
                jsonschema.validate(instance=contents, schema=schema)
            except jsonschema.exceptions.ValidationError as e:
                app.logger.error(f"JSON Schema Validation Error: {e}")
                return jsonify({'error': "Invalid JSON format."}), 400


            # Create a temporary file with a unique name within the application's instance path
            temp_dir = tempfile.mkdtemp(dir=app.instance_path)
            temp_file_path = os.path.join(temp_dir, str(uuid.uuid4()) + ".json")

            try:
                # Write the contents to the temporary file
                with open(temp_file_path, 'w') as f:
                    json.dump(contents, f)

                # Use json.load to safely parse the JSON data
                with open(temp_file_path, 'r') as f:
                    data = json.load(f)

                return jsonify(data), 200

            except json.JSONDecodeError as e:
                # Log detailed error internally
                app.logger.error(f"JSONDecodeError: {e}")
                return jsonify({'error': "Invalid JSON format."}), 400
            except Exception as e:
                # Log detailed error internally
                app.logger.error(f"Error processing the request: {e}")
                return jsonify({'error': "Error processing the request."}), 500
            finally:
                # Clean up the temporary file and directory
                try:
                    os.remove(temp_file_path)
                    os.rmdir(temp_dir)
                except OSError as e:
                    app.logger.error(f"Error cleaning up temporary files: {e}")
        except Exception as e:
            app.logger.error(f"Error processing the request: {e}")
            return jsonify({'error': "Error processing the request."}), 500
    else:
        return "Method not allowed. Use POST.", 405


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

