import os
import subprocess
from flask import Flask, request, abort
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "example.net"]  # Add your allowed domains
PING_COMMAND = "/bin/ping"  # Or wherever ping is located.  Make this STATIC.

def is_valid_url(url):
    """
    Validates the URL and checks if the domain is in the allowlist.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc, result.path != ''])
    except:
        return False

def is_allowed_domain(url):
    """
    Checks if the domain of the URL is in the allowlist.
    """
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS
    except:
        return False

def sanitize_url(url):
    """
    Sanitizes the URL by removing potentially harmful characters.
    This is a basic example and might need to be adjusted based on your needs.
    """
    # Remove characters that could be used for command injection
    sanitized_url = "".join(char for char in url if char.isalnum() or char in ['.', '/', ':', '-', '_'])
    return sanitized_url

@app.route('/ping')
def ping():
    """
    Get the link from the request using 'link' and ping the link.
    :return: link
    """
    link = request.args.get('link')

    if not link:
        return "Error: No link provided", 400

    if not is_valid_url(link):
        return "Error: Invalid URL", 400

    if not is_allowed_domain(link):
        return "Error: Domain not allowed", 403

    sanitized_link = sanitize_url(link)

    # Construct the ping command using subprocess.list2cmdline to properly escape arguments
    command = [PING_COMMAND, "-c", "3", sanitized_link]  # Limit to 3 pings
    
    try:
        # Execute the command in a subprocess with limited privileges (if possible)
        # Consider using a chroot jail or other sandboxing techniques for enhanced security.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False) # shell=False is crucial
        stdout, stderr = process.communicate(timeout=10)  # Add a timeout to prevent hanging

        if process.returncode == 0:
            return f"Ping successful:\n{stdout.decode()}"
        else:
            return f"Ping failed:\n{stderr.decode()}", 500

    except subprocess.TimeoutExpired:
        process.kill()
        return "Error: Ping timed out", 500
    except FileNotFoundError:
        return "Error: Ping command not found", 500
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), ssl_context='adhoc') # Use HTTPS

