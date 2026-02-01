import tempfile
import os
from flask import Flask, request, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory for temporary files
TEMP_DIR = "temp_files"  # Relative path
os.makedirs(TEMP_DIR, exist_ok=True)  # Create the directory if it doesn't exist


def is_safe_path(basedir, path):
    """
    Checks if the given path is safe and within the basedir.
    """
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return basedir == os.path.commonpath((basedir, abs_path))


@app.route('/write_temp')
def write_results():
    """
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    """
    results = request.args.get('results')

    if not results:
        return "Error: 'results' parameter is missing.", 400

    try:
        # Create a temporary file within the safe directory
        with tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', delete=False, dir=TEMP_DIR, suffix=".txt") as temp_file:
            temp_file.write(results)
            temp_file_path = temp_file.name

        # Ensure the path is safe before returning it.  This is a critical security check.
        if not is_safe_path(os.path.abspath(TEMP_DIR), os.path.relpath(temp_file_path, TEMP_DIR)):
            os.remove(temp_file_path)  # Clean up the file if it's not safe
            return "Error: Insecure file path detected.", 400

        return temp_file_path, 200

    except Exception as e:
        print(f"An error occurred: {e}")
        return "Error: Failed to write to temporary file.", 500


if __name__ == '__main__':
    app.run(debug=True)

