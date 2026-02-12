from urllib.parse import urlparse, urlunparse
import idna  # pip install idna

def is_valid_url_enhanced(url, max_length=2048):
    try:
        if not url or len(url) > max_length:
            return False

        # Normalize the URL
        parsed_url = urlparse(url)
        normalized_url = urlunparse(parsed_url)

        # Parse the normalized URL
        result = urlparse(normalized_url)

        if not all([result.scheme in ['http', 'https'], result.netloc]):
            return False

        # Handle IDN encoding to prevent homograph attacks (visually similar characters)
        try:
            netloc = result.netloc.encode('idna').decode('ascii')
        except UnicodeError:
            return False

        # Basic domain blacklist (replace with a real blacklist from a reputable source)
        # Example: a known phishing domain
        blacklisted_domains = ["evilcorp.com"]
        if netloc in blacklisted_domains:
            return False

        # Additional checks can be added here, such as checking for
        # suspicious characters in the path or query parameters.

        return True

    except Exception as e:
        print(f"URL Validation Error: {e}")  # Log the error
        return False

# Example Content Security Policy (CSP) header:
# Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';

import subprocess
import shlex
import os
import re  # Import the regular expression module

def execute_command_secure(command, args=None, allowed_commands=["ls", "pwd"]):
    """
    Executes a command from a very limited allowlist, with strict input sanitization.
    Use with extreme caution.  Avoid command execution if possible.
    """
    if command not in allowed_commands:
        raise ValueError("Command not allowed")

    # Sanitize arguments (example: allow only alphanumeric, underscores, hyphens, and periods)
    # This is just an example; the allowed characters will depend on the command.
    if args:
        sanitized_args = []
        for arg in args:
            if not isinstance(arg, str):
                raise ValueError("Arguments must be strings")

            # Example sanitization using a regular expression
            sanitized_arg = re.sub(r"[^a-zA-Z0-9_\-\.]", "", arg)  # Remove disallowed characters
            if sanitized_arg != arg:
                print(f"Warning: Argument '{arg}' was sanitized to '{sanitized_arg}'")
            sanitized_args.append(sanitized_arg)
    else:
        sanitized_args = []

    try:
        # Using subprocess.run with a list of arguments is a form of parameterization,
        # which helps prevent command injection.  However, input validation is still essential.
        command_list = [command] + sanitized_args  # Build the command list
        result = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=10)
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, str(e)
    except FileNotFoundError:
        return "", "Command not found"
    except OSError as e:
        return "", f"OS Error: {e}"
    except Exception as e:
        print(f"Unexpected error: {e}")
        return "", "An unexpected error occurred."

# Example usage:
# output, error = execute_command_secure("ls", args=["-l", "/tmp"])  # Example with arguments

