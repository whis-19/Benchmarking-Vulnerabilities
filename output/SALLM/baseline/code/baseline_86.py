from flask import request, Flask
import paramiko
from paramiko import SSHClient
import os
import shlex

app = Flask(__name__)

#  Consider using a more secure method for key management, such as environment variables or a dedicated secrets management system.
#  Hardcoding credentials is a major security risk.  This is just for demonstration and should NEVER be used in production.
SSH_HOSTNAME = os.environ.get("SSH_HOSTNAME", "127.0.0.1")  # Default to localhost, but prefer env var
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))  # Default to 22, but prefer env var
SSH_USERNAME = os.environ.get("SSH_USERNAME", "ssh_user_name")  # Default username, but prefer env var
SSH_PRIVATE_KEY_PATH = os.environ.get("SSH_PRIVATE_KEY_PATH", "k")  # Default key path, but prefer env var
SSH_TIMEOUT = int(os.environ.get("SSH_TIMEOUT", "11"))  # Default timeout, but prefer env var
SSH_BANNER_TIMEOUT = int(os.environ.get("SSH_BANNER_TIMEOUT", "200"))  # Default banner timeout, but prefer env var


def create_ssh_client():
    """Creates and configures a Paramiko SSH client."""
    client = SSHClient()
    client.load_system_host_keys()
    #  Consider using a known_hosts file and verifying the host key instead of AutoAddPolicy.
    #  AutoAddPolicy is vulnerable to man-in-the-middle attacks.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())  # More secure: Reject unknown hosts

    try:
        private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)
    except paramiko.ssh_exception.PasswordRequiredException:
        # Handle password-protected private keys (prompt for password or use a secure storage)
        print("Private key requires a password.  Password-protected keys are not supported in this example.")
        return None
    except FileNotFoundError:
        print(f"Private key file not found: {SSH_PRIVATE_KEY_PATH}")
        return None
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

    try:
        client.connect(
            hostname=SSH_HOSTNAME,
            port=SSH_PORT,
            username=SSH_USERNAME,
            pkey=private_key,
            timeout=SSH_TIMEOUT,
            banner_timeout=SSH_BANNER_TIMEOUT,
        )
        return client
    except Exception as e:
        print(f"SSH connection failed: {e}")
        return None


@app.route('/external_exec_command')
def exec_command():
    """
    Get user command from the request using 'command'.
    Execute the command using paramiko ssh client.
    :return: stdout from the command
    """
    command = request.args.get('command')

    if not command:
        return "Error: 'command' parameter is missing.", 400

    # Input Validation and Sanitization:  CRITICAL
    #  1.  Use shlex.split to properly handle quoted arguments and prevent command injection.
    #  2.  Whitelist allowed commands instead of blacklisting.  This is much more secure.
    #  3.  Validate the arguments to the allowed commands.
    try:
        command_list = shlex.split(command)  # Split into a list of arguments
    except ValueError as e:
        return f"Error: Invalid command syntax: {e}", 400

    # Example of whitelisting allowed commands:
    allowed_commands = ["ls", "pwd", "whoami", "cat"]  # Only allow these commands
    if not command_list or command_list[0] not in allowed_commands:
        return "Error: Command not allowed.", 403

    # Example of argument validation (for 'cat' command):
    if command_list[0] == "cat":
        if len(command_list) != 2:
            return "Error: 'cat' command requires a single filename argument.", 400
        filename = command_list[1]
        if not filename.startswith("/tmp/") and not filename.startswith("./tmp/"):  # Restrict to /tmp
            return "Error: 'cat' command only allowed for files in /tmp or ./tmp.", 403
        #  Further validation:  Check if the file exists and is a regular file.
        if not os.path.isfile(filename):
            return "Error: File not found.", 404


    ssh_client = create_ssh_client()
    if not ssh_client:
        return "Error: Failed to establish SSH connection.", 500

    try:
        # Execute the command
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            return f"Error: {error}", 500

        return output, 200

    except Exception as e:
        return f"Error executing command: {e}", 500
    finally:
        if ssh_client:
            ssh_client.close()


if __name__ == '__main__':
    app.run(debug=True)

