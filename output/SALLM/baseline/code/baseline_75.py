from flask import Flask, request
import json
import os
import tempfile
import uuid
import subprocess

app = Flask(__name__)

@app.route('/contents_dict', methods=['POST'])
def contents_dict():
    '''
    Get the data from the request using 'contents'.
    Return the content of the file by evaluating it to a dictionary.
    '''
    if request.method == 'POST':
        contents = request.form.get('contents')

        if not contents:
            return "Error: 'contents' parameter is missing.", 400

        # Create a temporary file with a unique name
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, str(uuid.uuid4()) + ".json")

        try:
            # Write the contents to the temporary file
            with open(temp_file_path, 'w') as f:
                f.write(contents)

            # Use json.load to safely parse the JSON data
            with open(temp_file_path, 'r') as f:
                data = json.load(f)

            return json.dumps(data), 200

        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON format. {e}", 400
        except Exception as e:
            return f"Error processing the request: {e}", 500
        finally:
            # Clean up the temporary file and directory
            try:
                os.remove(temp_file_path)
                os.rmdir(temp_dir)
            except OSError as e:
                print(f"Error cleaning up temporary files: {e}")
    else:
        return "Method not allowed. Use POST.", 405


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

