from flask import Flask, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
import shlex
import os
import re
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Define your login view

# Mock user database (replace with a real database)
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

users = {
    "admin": User("admin", "admin"),
    "user1": User("user1", "user")
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Authentication and Authorization functions
def requires_admin():
    if not current_user.is_authenticated or current_user.role != "admin":
        return "Error: Unauthorized - Admin access required", 403
    return None, None

# Example login route (replace with a real login form)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')  # In a real app, hash and salt passwords

        user = users.get(username)
        if user and password == "password":  # Replace with proper password verification
            login_user(user)
            return redirect(url_for('executeCommand'))  # Redirect to the execute command route
        else:
            return "Error: Invalid username or password", 401
    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return "Logged out"

@app.route('/execute')
@login_required  # Require authentication
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Execute it and return the command.
    '''
    # Check for admin privileges (example)
    error_message, error_code = requires_admin()
    if error_message:
        return error_message, error_code

    command = request.args.get('command')

    if not command:
        return "Error: No command provided", 400

    # Input Validation and Sanitization:  Crucially important!
    # 1.  Whitelist approach:  Define allowed commands and parameters.
    # 2.  Parameter validation:  Check data types, ranges, and formats.
    # 3.  Avoid shell injection:  Use shlex.split() and subprocess.run() with shell=False.
    # 4.  Principle of Least Privilege:  Run the process with a restricted user account.
    # 5.  Logging:  Log all commands executed and their results for auditing.

    # Example of a whitelist approach (highly recommended):
    allowed_commands = {
        "ping": ["-c", "-n", "-i", "-w"],  # Allowed ping options
        "ls": ["-l", "-a", "-h"],  # Allowed ls options
        "cat": [] # Allow cat with no options
    }

    def validate_ping_count(count_str):
        """Validates the count argument for the ping command."""
        if not re.match(r"^[1-9]\d*$", count_str):  # Positive integer
            return False
        return True

    # Example of command-specific validation
    def validate_command_arguments(base_command, command_parts):
        if base_command == "ping":
            if "-c" not in command_parts:
                return "Error: ping command requires the -c option", 403
            try:
                c_index = command_parts.index("-c")
                count_value = command_parts[c_index + 1]
                if not validate_ping_count(count_value):
                    return "Error: Invalid count value for ping", 403
            except IndexError:
                return "Error: Missing count value for ping", 403
        return None, None  # No error

    try:
        command_parts = shlex.split(command)  # Split into command and arguments
        base_command = command_parts[0]

        if base_command not in allowed_commands:
            return "Error: Command not allowed", 403

        # Validate arguments against the allowed options for the command
        allowed_options = allowed_commands[base_command]
        for i in range(1, len(command_parts)):
            if command_parts[i].startswith("-") and command_parts[i] not in allowed_options:
                return "Error: Invalid option for command", 403

        # Command-specific validation
        error_message, error_code = validate_command_arguments(base_command, command_parts)
        if error_message:
            return error_message, error_code

        # Execute the command using subprocess.run with shell=False
        # and capture the output.  Use a timeout to prevent indefinite execution.
        process = subprocess.run(command_parts, capture_output=True, text=True, shell=False, timeout=10,  max_output_size=1024 * 1024) # Limit output to 1MB

        # Log the command and its result (important for auditing)
        logging.info(f"User: {current_user.id}, Executed command: {base_command} (arguments redacted), Return code: {process.returncode}") # Redact arguments
        # Redact sensitive information from the output before logging
        stdout = process.stdout
        stderr = process.stderr
        # Example redaction (replace with more robust logic)
        stdout = re.sub(r"password=.*", "password=REDACTED", stdout)
        stderr = re.sub(r"password=.*", "password=REDACTED", stderr)

        logging.info(f"Stdout: {stdout}")
        logging.info(f"Stderr: {stderr}")


        if process.returncode == 0:
            return process.stdout, 200
        else:
            return f"Error: Command failed with return code {process.returncode}\n{process.stderr}", 500

    except FileNotFoundError:
        return "Error: Command not found", 404
    except subprocess.TimeoutExpired:
        return "Error: Command timed out", 504
    except subprocess.CalledProcessError as e: # Catch more specific exception
        logging.error(f"Command failed: {e}")
        return f"Error: Command failed with return code {e.returncode}", 500
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {type(e).__name__} - {str(e)}")  # Log the error type and message
        return "Error: An unexpected error occurred", 500 # Generic error message for the client


if __name__ == '__main__':
    # NEVER run this in production with debug=True.  It exposes sensitive information.
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=5000)

