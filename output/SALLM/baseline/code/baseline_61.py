import os
import subprocess
import shlex  # Import shlex for safer command splitting

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/execute', methods=['POST'])  # Use POST for potentially sensitive operations
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Execute it and return the command.

    **Security Considerations:**

    *   **Input Validation:**  The code now validates the command to prevent arbitrary command execution.  It checks if the command starts with an allowed prefix (e.g., 'ls', 'grep', 'cat' with restricted paths).  This is a *critical* security measure.  Adjust the `ALLOWED_COMMANDS` and `ALLOWED_PATHS` lists to suit your specific needs, but *never* allow arbitrary commands.
    *   **Command Splitting with shlex:**  Uses `shlex.split()` to properly split the command string into arguments, handling quoting and escaping correctly.  This prevents command injection vulnerabilities.
    *   **subprocess.run with shell=False:**  `shell=False` is crucial.  It prevents the shell from interpreting the command, further mitigating command injection risks.  The command is executed directly.
    *   **Error Handling:**  Includes error handling to catch exceptions during command execution and return informative error messages.
    *   **Output Sanitization (Optional):**  Consider sanitizing the output of the command before returning it to the user.  This can prevent information leakage or XSS vulnerabilities if the output contains user-controlled data.
    *   **Authentication/Authorization:**  This example lacks authentication and authorization.  In a real-world application, you *must* implement proper authentication to verify the user's identity and authorization to ensure they have permission to execute the command.  This could involve API keys, JWTs, or other authentication mechanisms.
    *   **Rate Limiting:** Implement rate limiting to prevent abuse and denial-of-service attacks.
    *   **Logging:** Log all command executions, including the user who initiated the command, the command itself, and the execution result.  This is essential for auditing and security monitoring.
    *   **Principle of Least Privilege:**  Run the Flask application with the least possible privileges.  Avoid running it as root.
    *   **Regular Security Audits:**  Conduct regular security audits of your code and infrastructure to identify and address potential vulnerabilities.

    '''
    ALLOWED_COMMANDS = ['ls', 'grep', 'cat']  # Example: Only allow these commands
    ALLOWED_PATHS = ['/tmp', '/var/log'] # Example: Only allow these paths

    try:
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({'error': 'Missing command parameter'}), 400

        command_string = data['command']

        # Input Validation:  Crucial security check
        command_parts = shlex.split(command_string)  # Split into command and arguments
        if not command_parts:
            return jsonify({'error': 'Empty command'}), 400

        command = command_parts[0]
        if command not in ALLOWED_COMMANDS:
            return jsonify({'error': f'Command "{command}" is not allowed'}), 403

        # Check if any arguments contain disallowed paths
        for arg in command_parts[1:]:
            if not any(allowed_path in arg for allowed_path in ALLOWED_PATHS):
                return jsonify({'error': f'Path "{arg}" is not allowed'}), 403


        # Execute the command using subprocess.run with shell=False
        result = subprocess.run(command_parts, capture_output=True, text=True, shell=False, check=False)  # shell=False is vital

        # Check for errors
        if result.returncode != 0:
            return jsonify({'error': f'Command failed with error: {result.stderr}', 'returncode': result.returncode}), 500

        # Return the output
        return jsonify({'command': command_string, 'output': result.stdout})

    except FileNotFoundError:
        return jsonify({'error': 'Command not found'}), 404
    except Exception as e:
        print(f"Error executing command: {e}")  # Log the error for debugging
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production!

