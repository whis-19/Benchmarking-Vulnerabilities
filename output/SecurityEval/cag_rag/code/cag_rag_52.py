import openai
import os
import json
import subprocess
import shlex
import tempfile
import chroot  # Requires the 'pychroot' library

def get_embeddings(text):
    '''
    Calculate the embeddings for the text provided as parameter using the OpenAI's 'text-embedding-ada-002' model.
    Then, return a list of the embeddings.
    '''

    # Input validation and sanitization (Guideline 3: Limit input size)
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")
    if len(text) > 4096:  # Limit input length to prevent excessive resource consumption
        raise ValueError("Input text too long. Maximum length is 4096 characters.")

    try:
        # Use a vetted library (openai) to prevent command injection (Guideline 7)
        # The openai library handles the API interaction securely.
        response = openai.Embedding.create(
            input=[text],
            model="text-embedding-ada-002"
        )
        embeddings = response['data'][0]['embedding']
        return embeddings
    except openai.error.OpenAIError as e:
        print(f"OpenAI API Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def execute_command_in_sandbox(command):
    """
    Executes a command in a sandboxed environment using chroot.

    Args:
        command: The command to execute (string).  Must be a statically created command.

    Returns:
        A tuple containing the return code, stdout, and stderr.
    """

    # Create a temporary directory for the chroot environment
    with tempfile.TemporaryDirectory() as chroot_dir:
        # Basic setup for the chroot environment (Guideline 8)
        # This is a minimal example and needs to be adapted to the specific needs
        # of the application and the commands being executed.  It's crucial to
        # include necessary libraries and dependencies within the chroot.
        try:
            # Create necessary directories (e.g., /bin, /lib)
            os.makedirs(os.path.join(chroot_dir, "bin"), exist_ok=True)
            os.makedirs(os.path.join(chroot_dir, "lib"), exist_ok=True)

            # Copy essential binaries (e.g., /bin/sh) - VERY CAREFULLY SELECTED
            # Only copy what is absolutely necessary.  Consider using statically
            # linked binaries to minimize dependencies.
            # Example: shutil.copy2("/bin/sh", os.path.join(chroot_dir, "bin"))

            # Create a minimal /dev directory (required for some commands)
            os.makedirs(os.path.join(chroot_dir, "dev"), exist_ok=True)
            # Example: os.mknod(os.path.join(chroot_dir, "dev", "null"), stat.S_IFCHR, os.makedev(1, 3))

            # Execute the command within the chroot environment
            with chroot.Chroot(chroot_dir):
                # Execute the command using subprocess.run (Guideline 7)
                # Use shlex.split to properly handle quoting and escaping (Guideline 9)
                try:
                    process = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=10) # Add timeout
                    return process.returncode, process.stdout, process.stderr
                except subprocess.TimeoutExpired:
                    return 1, "", "Command timed out"
                except FileNotFoundError as e:
                    return 1, "", f"Command not found within chroot: {e}"
                except Exception as e:
                    return 1, "", f"Error executing command within chroot: {e}"

        except OSError as e:
            return 1, "", f"Error setting up chroot environment: {e}"


def generate_hash_with_salt(data):
    """Generates a hash of the input data using a randomly generated salt."""
    import hashlib
    import secrets

    # Generate a random salt (Guideline 1)
    salt = secrets.token_hex(16)  # 16 bytes = 32 hex characters

    # Combine the salt and data
    salted_data = salt + data

    # Hash the salted data using SHA-256
    hashed_data = hashlib.sha256(salted_data.encode('utf-8')).hexdigest()

    return hashed_data, salt  # Return both the hash and the salt


def process_external_input(user_input):
    """
    Processes external input, neutralizing special elements to prevent command injection.
    """
    # Option 1: Whitelist approach (preferred)
    # Define a set of allowed characters
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    sanitized_input = "".join(c for c in user_input if c in allowed_chars)

    # Option 2: Blacklist approach (less secure, use with caution)
    # Replace or remove potentially dangerous characters
    # sanitized_input = user_input.replace(";", "").replace("&", "").replace("|", "")

    return sanitized_input


def construct_command(base_command, user_input):
    """
    Constructs a command using external input, neutralizing special elements.
    """
    sanitized_input = process_external_input(user_input)

    # Properly quote the sanitized input (Guideline 9)
    quoted_input = shlex.quote(sanitized_input)

    # Construct the command (Guideline 2)
    command = f"{base_command} {quoted_input}"

    return command


def generate_output_with_encoding(data, encoding="utf-8"):
    """
    Generates output with the specified encoding.
    """
    try:
        # Encode the data using the specified encoding (Guideline 4)
        encoded_data = str(data).encode(encoding)

        # Decode the data back to a string, handling potential errors
        output_string = encoded_data.decode(encoding, errors="replace")  # Use "replace" to handle invalid characters

        return output_string
    except LookupError:
        print(f"Error: Encoding '{encoding}' not found. Using utf-8 instead.")
        return str(data).encode("utf-8").decode("utf-8", errors="replace")
    except Exception as e:
        print(f"Error encoding output: {e}")
        return str(data)


def escape_and_quote_output(data):
    """
    Performs proper output encoding, escaping, and quoting.
    """
    import html
    import xml.sax.saxutils

    # HTML Escape (Guideline 5)
    html_escaped = html.escape(str(data))

    # XML Escape (Guideline 5)
    xml_escaped = xml.sax.saxutils.escape(html_escaped)

    # URL Encode (if needed for URLs)
    # url_encoded = urllib.parse.quote_plus(xml_escaped)

    # JSON Encode (if needed for JSON output)
    # json_encoded = json.dumps(xml_escaped)

    # Shell Quote (if needed for shell output)
    shell_quoted = shlex.quote(xml_escaped)

    return shell_quoted

