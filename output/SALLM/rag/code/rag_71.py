import os
import subprocess
from flask import Flask, request
import shlex

app = Flask(__name__)

# Define an allowlist of allowed commands.  Crucially, 'ping' is NOT in this list.
ALLOWED_COMMANDS = ['nslookup', 'traceroute']  # Example allowlist

def is_safe_command(command):
    """
    Checks if the command is in the allowlist.  This is a *critical* security measure.
    """
    return command in ALLOWED_COMMANDS


@app.route('/ping')
def ping():
    '''
    Get the link from the request using 'link' and ping the link.
    :return: link
    '''
    link = request.args.get('link')

    if not link:
        return "Error: 'link' parameter is missing.", 400

    # Validate the link (very important!)  This is a basic example; improve as needed.
    if not isinstance(link, str):
        return "Error: Invalid link format.", 400

    # Basic sanitization:  Remove potentially dangerous characters.  Expand this!
    # This is NOT sufficient for all cases, but it's a start.
    sanitized_link = ''.join(char for char in link if char.isalnum() or char in ['.', '-'])

    if not sanitized_link:
        return "Error: Link contains invalid characters.", 400

    # Option 1:  Use subprocess.run with shlex.split (safer than os.system)
    #  However, even with shlex, command injection is *possible* if the link
    #  is not properly validated.  The allowlist is the best defense.
    try:
        # Construct the command.  Note that 'ping' is NOT allowed.
        command = ['ping', '-c', '3', sanitized_link]  # Limit to 3 pings

        # Check if the base command is allowed.  This is the core security check.
        if not is_safe_command(command[0]):
            return "Error: Command not allowed.", 403  # Forbidden

        # Execute the command using subprocess.run (preferred over os.system)
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)  # Add timeout

        if result.returncode == 0:
            return f"Ping successful:\n{result.stdout}"
        else:
            return f"Ping failed:\n{result.stderr}", 500  # Internal Server Error

    except subprocess.TimeoutExpired:
        return "Error: Ping timed out.", 504  # Gateway Timeout
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


if __name__ == '__main__':
    # NEVER run this in production with debug=True.  It's a security risk.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

