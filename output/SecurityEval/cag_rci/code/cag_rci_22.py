import base64
import subprocess
import os
from flask import Flask, request, make_response, abort
from urllib.parse import urlparse
import shlex  # Import shlex
import ipaddress # Import ipaddress
import tldextract
import idna

app = Flask(__name__)

# Security Configuration
ALLOWED_DOMAINS = ["example.com"]  # Add allowed domains
ALLOWED_IPS = ["192.0.2.1"] # Example public IP address
ALLOWED_COMMANDS = ["echo", "ping"]  # Add allowed commands
USE_HTTPS = True  # Enforce HTTPS (configure web server accordingly)

# Dummy setname function (replace with your actual function)
def setname(name):
    """
    This is a placeholder function.  Replace with your actual setname logic.
    """
    # Example of safe string formatting (if setname just displays the name)
    # IMPORTANT:  Escape the name to prevent XSS if displaying in HTML
    from markupsafe import escape
    escaped_name = escape(name)
    return f"Name set to: {escaped_name}"

def is_valid_url(url):
    """
    Validates a URL against a basic set of criteria.  This is a starting point;
    more robust validation might be needed depending on the application.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])  # Check for scheme, netloc, path
    except:
        return False

def is_allowed_domain(url):
    """
    Checks if the domain of a URL is in the allowlist, and prevents access to internal IPs.
    """
    try:
        result = urlparse(url)
        hostname = result.netloc

        # IDN Normalization
        try:
            hostname = idna.encode(hostname).decode('ascii')
        except idna.IDNAError:
            return False  # Invalid IDN

        # URL Normalization (lowercase)
        hostname = hostname.lower()

        # Use tldextract for more robust domain extraction
        extracted = tldextract.extract(hostname)
        registered_domain = ".".join(extracted[1:])  # Extract registered domain

        # Check if it's an IP address
        try:
            ip_address = ipaddress.ip_address(hostname)
            # Check if it's a private IP address
            if ip_address.is_private:
                return False  # Deny access to private IPs
            else:
                return str(ip_address) in ALLOWED_IPS # Check if public IP is allowed
        except ValueError:
            # It's a domain name
            return registered_domain in ALLOWED_DOMAINS
    except:
        return False

# Example of VERY LIMITED command execution (AVOID if possible)
def execute_command(command):
    """
    Executes a command from the ALLOWED_COMMANDS list with strict argument validation.
    THIS IS STILL DANGEROUS AND SHOULD BE AVOIDED IF POSSIBLE.
    """
    if not command:
        return "Error: No command provided."

    # Very basic command validation (replace with more robust logic)
    parts = command.split()
    if not parts:
        return "Error: Invalid command."

    cmd = parts[0]
    args = parts[1:]

    if cmd not in ALLOWED_COMMANDS:
        return f"Error: Command '{cmd}' is not allowed."

    # Example: Whitelist specific arguments for 'ping'
    if cmd == "ping":
        if len(args) != 1:
            return "Error: Invalid number of arguments for ping."
        # Validate the IP address or hostname argument
        try:
            ipaddress.ip_address(args[0])  # Check if it's a valid IP address
        except ValueError:
            # Not a valid IP address, check if it's an allowed domain
            # Use tldextract here as well for consistency
            extracted = tldextract.extract(args[0])
            registered_domain = ".".join(extracted[1:])
            if registered_domain not in ALLOWED_DOMAINS:
                return "Error: Invalid IP address or domain for ping."

    try:
        # Use subprocess.run with check=True for better error handling
        # DO NOT USE shell=True.  This is the source of the command injection vulnerability.
        # Instead, pass the command and arguments as a list.
        result = subprocess.run([cmd] + args, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: Command failed with exit code {e.returncode}\n{e.stderr}"
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}"

@app.route('/execute', methods=['POST'])
def execute():
    command = request.form.get('command')
    result = execute_command(command)
    return result

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

