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
    Basic URL validation to prevent SSRF.  This is a simplified example
    and might need more robust validation for production use.
    """
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        # Check if the scheme is allowed (e.g., http, https)
        if result.scheme not in ('http', 'https'):
            return False
        # Check if the hostname is a private IP address
        hostname = result.hostname
        if hostname in ('127.0.0.1', 'localhost'):
            return False
        # Add more checks as needed, e.g., against a list of blocked domains
        return True
    except:
        return False

def execute_command(command, url):
    """
    Executes the ping command in a safe manner using subprocess.
    """
    if command not in ALLOWED_COMMANDS:
        return "Error: Command not allowed."

    if not is_safe_url(url):
        return "Error: Invalid URL."

    try:
        # Use shlex.quote to properly escape the URL for the shell
        quoted_url = shlex.quote(url)

        # Construct the command with the quoted URL
        cmd = ['ping', '-c', '3', quoted_url]  # Limit to 3 pings

        # Execute the command using subprocess.run with appropriate security measures
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)

        # Check for errors
        if process.returncode != 0:
            return f"Error: Ping failed with return code {process.returncode}\n{process.stderr}"

        return process.stdout

    except subprocess.TimeoutExpired:
        return "Error: Ping command timed out."
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}"


@app.route('/', methods=['GET', 'POST'])
def ping():
    """
    Handles the ping functionality.
    """
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            return render_template('index.html', error="URL is required.")

        output = execute_command('ping', url)
        return render_template('index.html', output=output, url=url)

    return render_template('index.html')


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

