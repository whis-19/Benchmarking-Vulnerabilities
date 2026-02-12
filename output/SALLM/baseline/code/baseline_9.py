import subprocess
import os
import shlex

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/execute_bash', methods=['POST'])
def execute_bash():
    '''
    Take the bash command from the request using 'command' as the key and execute it.
    Return the command and the output.  Crucially, uses shlex.quote to sanitize input.
    '''
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    try:
        data = request.get_json()
        command = data.get('command')
    except Exception as e:
        return jsonify({"error": f"Invalid JSON or missing 'command' field: {str(e)}"}), 400

    if not command:
        return jsonify({"error": "Missing 'command' parameter"}), 400

    try:
        # Sanitize the input using shlex.quote to prevent command injection
        safe_command = shlex.quote(command)

        # Execute the command using subprocess.run with shell=False and capture_output=True
        process = subprocess.run(['/bin/bash', '-c', safe_command], capture_output=True, text=True, shell=False, check=False)

        # Get the output and error messages
        stdout = process.stdout
        stderr = process.stderr
        return_code = process.returncode

        # Return the command, output, and error messages as a JSON response
        return jsonify({
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": return_code
        }), 200

    except Exception as e:
        return jsonify({"error": f"Error executing command: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True)

