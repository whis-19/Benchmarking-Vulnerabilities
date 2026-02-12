import subprocess
import shlex
from flask import Flask, request, render_template, abort
import os

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging in production

# Define an allowlist of allowed commands
ALLOWED_COMMANDS = ['ping']

def is_safe_url(url):
    """
    Basic URL validation to prevent obvious abuse.  This is NOT a comprehensive
    security measure and should be augmented with more robust checks if needed.
    """
    if not url:
        return False
    if url.startswith('http://') or url.startswith('https://'):
        return False  # Disallow external URLs for now
    if ".." in url or "/" in url:
        return False # Disallow path traversal
    return True

def execute_command(command, url):
    """
    Executes a command using subprocess.  Uses shlex.quote to properly escape
    the URL argument.  This is safer than string formatting.
    """
    try:
        # Construct the command with proper escaping
        cmd = [command, shlex.quote(url)]

        # Execute the command in a sandboxed environment (example using chroot)
        # Note: Setting up a proper chroot environment is complex and beyond the scope
        # of this example.  This is just a placeholder.  Consider using more robust
        # sandboxing techniques like Docker or VMs.
        #
        # Example (requires chroot setup):
        # chroot_path = "/path/to/chroot/jail"
        # cmd = ["chroot", chroot_path] + cmd

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        output, error = process.communicate()

        if error:
            return f"Error: {error.decode('utf-8')}"
        else:
            return output.decode('utf-8')

    except FileNotFoundError:
        return "Error: Command not found."
    except Exception as e:
        return f"Error: {str(e)}"


@app.route('/', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        url = request.form.get('url')

        if not url:
            return "Error: URL is required."

        if not is_safe_url(url):
            return "Error: Invalid URL."

        command = 'ping'  # Hardcoded command from the allowlist

        if command not in ALLOWED_COMMANDS:
            return "Error: Command not allowed."

        output = execute_command(command, url)
        return render_template('ping_result.html', output=output)

    return render_template('ping_form.html')


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(host='0.0.0.0', port=5000)

