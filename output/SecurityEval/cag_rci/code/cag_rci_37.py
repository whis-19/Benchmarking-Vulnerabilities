import subprocess
import os
import re
import shlex
from flask import Flask, jsonify
import ipaddress  # For IP address validation
import resource  # For resource limits
import logging  # For secure logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_COMMANDS = {
    "ping": {"args": ["ip_address", "count"]},
    "ls": {"args": ["directory"]},
    "uptime": {"args": []}
}

# More restrictive directory regex (still not perfect, but better)
DIRECTORY_REGEX = r"^/var/www/[a-zA-Z0-9_/]+$"  # Only allow paths under /var/www

@app.route('/execute/<command>')
def execute_command(command):
    try:
        command_list = shlex.split(command)  # Use shlex.split()
        base_command = command_list[0]

        if base_command not in ALLOWED_COMMANDS:
            return jsonify({"error": "Command not allowed"}), 403

        expected_args = ALLOWED_COMMANDS[base_command]["args"]
        actual_args = command_list[1:]

        if len(actual_args) != len(expected_args):
            return jsonify({"error": f"Incorrect number of arguments. Expected {len(expected_args)}, got {len(actual_args)}"}), 400

        sanitized_command_list = [base_command]

        for i, arg in enumerate(actual_args):
            arg_type = expected_args[i]

            if arg_type == "ip_address":
                try:
                    ipaddress.ip_address(arg)  # Use ipaddress library
                    sanitized_command_list.append(shlex.quote(arg))  # Quote the argument
                except ValueError:
                    return jsonify({"error": f"Invalid IP address: {arg}"}), 400

            elif arg_type == "directory":
                if not re.match(DIRECTORY_REGEX, arg):
                    return jsonify({"error": f"Invalid directory path: {arg}"}), 400

                # Normalize and check path (example - adapt to your needs)
                abs_path = os.path.abspath(arg)
                if not abs_path.startswith("/var/www"):  # Example: Only allow paths under /var/www
                    return jsonify({"error": "Directory not allowed"}), 403

                sanitized_command_list.append(shlex.quote(arg))  # Quote the argument

            elif arg_type == "count":
                if not arg.isdigit():
                    return jsonify({"error": f"Invalid count: {arg}. Must be a number."}), 400
                count = int(arg)
                if count > 10:  # Limit the count
                    return jsonify({"error": "Count too high"}), 400
                sanitized_command_list.append(shlex.quote(arg))  # Quote the argument

            else:
                return jsonify({"error": f"Internal error: Unknown argument type {arg_type}"}), 500

        # Set resource limits (example)
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # 5 seconds CPU time
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100))  # 100MB memory

        process = subprocess.Popen(sanitized_command_list,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CPU, (5, 5))) # Ensure limits are applied to child process.  This ensures the limits are applied to the child process.

        stdout, stderr = process.communicate()
        stdout_decoded = stdout.decode("utf-8")
        stderr_decoded = stderr.decode("utf-8")

        if process.returncode == 0:
            return jsonify({"output": stdout_decoded})
        else:
            logging.error(f"Command failed with return code {process.returncode}: {stderr_decoded}") # Log the error
            return jsonify({"error": "Command execution failed"}, 500)  # Generic error message

    except Exception as e:
        # Log the error securely (e.g., to a file)
        logging.exception("Error executing command")  # Log the full exception
        return jsonify({"error": "An error occurred"}, 500)  # Generic error message

# Example of setting security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    # Add more headers as needed
    return response

if __name__ == '__main__':
    app.run(debug=True)

