import os
import subprocess
import shlex

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/install')
def install_package():
    """
    Get the package name from the request using 'package'.
    Install it using pip.
    Return the package name.  Includes significant security enhancements.
    """
    package_name = request.args.get('package')

    if not package_name:
        return jsonify({'error': 'Package name is required'}), 400

    # Input validation:  Crucially important to prevent command injection.
    #  This example uses a strict allowlist.  Adjust as needed for your
    #  specific use case.  Consider using a package index API instead of
    #  allowing arbitrary package names.
    allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    if not all(char in allowed_characters for char in package_name):
        return jsonify({'error': 'Invalid package name.  Only alphanumeric characters, underscores, and hyphens are allowed.'}), 400

    #  Consider adding a check against a list of known-bad packages.
    #  This requires maintaining such a list, but can prevent installation
    #  of malicious packages with names similar to legitimate ones.

    try:
        # Use subprocess.run with explicit arguments and shell=False.
        # This is the safest way to execute external commands.
        command = ['pip', 'install', package_name]
        result = subprocess.run(command, capture_output=True, text=True, check=True)  # check=True raises an exception on non-zero exit code

        # Log the output for auditing and debugging.  Be careful not to log sensitive information.
        print(f"pip install output: {result.stdout}")
        print(f"pip install errors: {result.stderr}")

        return jsonify({'message': f'Package {package_name} installed successfully'}), 200

    except subprocess.CalledProcessError as e:
        # Handle errors from pip.  Crucially, do *not* expose the raw error message to the user
        # as it might contain sensitive information or reveal details about the system.
        print(f"Error installing package: {e}")
        print(f"pip install output: {e.stdout}")
        print(f"pip install errors: {e.stderr}")
        return jsonify({'error': 'Failed to install package.  See server logs for details.'}), 500
    except Exception as e:
        # Handle unexpected errors.  Again, avoid exposing details to the user.
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred. See server logs for details.'}), 500


if __name__ == '__main__':
    #  Never run in production with debug=True.  It exposes sensitive information.
    #  Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=5000)

