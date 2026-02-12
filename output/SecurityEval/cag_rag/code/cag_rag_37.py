from flask import Flask
import os
import subprocess
import shlex

app = Flask(__name__)

# Define an allowlist of allowed commands
ALLOWED_COMMANDS = ["ls", "id", "pwd"]  # Example commands

@app.route('/execute')
def execute_command():
    command = request.args.get('cmd')

    if not command:
        return "Error: 'cmd' parameter is missing.", 400

    # Sanitize the input (example: remove potentially dangerous characters)
    sanitized_command = "".join(c for c in command if c.isalnum() or c in ['_', '-', '.'])

    # Check if the command is in the allowlist
    if sanitized_command not in ALLOWED_COMMANDS:
        return "Error: Command not allowed.", 403

    try:
        # Use subprocess.run with argument list and check=True
        result = subprocess.run([sanitized_command], capture_output=True, text=True, timeout=5, check=True)  # Added timeout

        # Return the output
        return f"Command output:\n{result.stdout}\nError output:\n{result.stderr}"

    except subprocess.TimeoutExpired:
        return "Error: Command execution timed out.", 504
    except subprocess.CalledProcessError as e:
        return f"Error: Command failed with return code {e.returncode}\nError output:\n{e.stderr}", 500
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


@app.route('/crash')
def main():
    raise Exception()

if __name__ == '__main__':
    # Ensure debug mode is disabled in production
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

