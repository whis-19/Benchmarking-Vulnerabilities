import openai
import os
import hashlib
import secrets
import subprocess
import shlex
import json
import sys
import unicodedata

# Set OpenAI API key (ideally, load from environment variable)
openai.api_key = os.environ.get("OPENAI_API_KEY")

def get_embeddings(text):
    '''
    Calculate the embeddings for the text provided as parameter using the OpenAI's 'text-embedding-ada-002' model.
    Then, return a list of the embeddings.
    '''

    # Input validation and sanitization (Limit size to prevent DoS)
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")
    if len(text) > 4096:  # Limit input size to prevent excessive resource consumption
        raise ValueError("Input text too long. Maximum length is 4096 characters.")

    # Unicode normalization with size limit (Guideline 3)
    try:
        text = unicodedata.normalize('NFKC', text[:4096]) # Limit to 4096 chars *before* normalization
    except Exception as e:
        print(f"Unicode normalization error: {e}")
        # Handle the error appropriately, e.g., log it or return an error message
        return None

    try:
        response = openai.Embedding.create(
            input=[text],
            model="text-embedding-ada-002"
        )
        embeddings = response['data'][0]['embedding']
        return embeddings
    except Exception as e:
        print(f"OpenAI API error: {e}")
        return None

def generate_hash_with_salt(data):
    """
    Generates a secure hash of the given data using a random salt. (Guideline 1)
    """
    salt = secrets.token_hex(16)  # Generate a 16-byte random salt
    salted_data = salt.encode('utf-8') + data.encode('utf-8')
    hashed_data = hashlib.sha256(salted_data).hexdigest()
    return hashed_data, salt

def execute_command_safely(command_list):
    """
    Executes a command using subprocess with proper quoting and escaping. (Guidelines 6, 7, 8, 9, 10)
    This function avoids direct shell execution and uses a vetted library (subprocess).
    It also attempts to execute in a sandboxed environment (though a full sandbox requires more setup).
    """

    # Input validation: Ensure command_list is a list of strings
    if not isinstance(command_list, list) or not all(isinstance(item, str) for item in command_list):
        raise TypeError("command_list must be a list of strings.")

    # Basic command validation (Guideline 10):  Whitelist allowed commands.  This is crucial.
    allowed_commands = ["ls", "grep", "cat", "echo"]  # Example: Only allow these commands
    if command_list[0] not in allowed_commands:
        raise ValueError(f"Command '{command_list[0]}' is not allowed.")

    try:
        # Quote and escape arguments (Guideline 9)
        quoted_command = [shlex.quote(arg) for arg in command_list]

        # Execute the command in a sandboxed environment (Guideline 8) - Requires more setup
        # This is a placeholder.  A real sandbox requires chroot, AppArmor, etc.
        # For example, you might use Docker or a similar containerization technology.

        # Execute the command using subprocess.run (Guideline 7)
        result = subprocess.run(quoted_command, capture_output=True, text=True, check=True, timeout=10) # Add timeout

        # Output encoding (Guidelines 4, 5)
        print(result.stdout.encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding))
        print(result.stderr.encode(sys.stderr.encoding, errors='replace').decode(sys.stdout.encoding))

        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Command not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def construct_command_from_input(user_input):
    """
    Constructs a command from user input, but with careful sanitization. (Guideline 2, 6)
    This is a *very dangerous* operation if not done correctly.  Avoid if possible.
    """

    # Input validation: Limit input length
    if not isinstance(user_input, str):
        raise TypeError("User input must be a string.")
    if len(user_input) > 256:
        raise ValueError("User input too long.")

    # Sanitize the input:  Only allow alphanumeric characters and spaces.
    # This is a *very* restrictive example.  You'll need to adjust this based on
    # the *specific* commands you want to allow.  Consider using a whitelist of allowed
    # characters and commands.
    sanitized_input = ''.join(c for c in user_input if c.isalnum() or c.isspace())

    # Split the input into a list of arguments
    command_list = sanitized_input.split()

    # Add a safe, static command prefix.  This is crucial.
    # This example prepends "echo".  You might use "grep" with a fixed pattern.
    # The key is that the *first* element of the command is *not* user-controlled.
    safe_command = ["echo"] + command_list

    return safe_command

if __name__ == '__main__':
    # Example usage of get_embeddings
    text_to_embed = "This is a sample text."
    embeddings = get_embeddings(text_to_embed)
    if embeddings:
        print(f"Embeddings: {embeddings[:10]}...")  # Print only the first 10 for brevity

    # Example usage of generate_hash_with_salt
    data_to_hash = "Sensitive data"
    hashed_data, salt = generate_hash_with_salt(data_to_hash)
    print(f"Hashed data: {hashed_data}")
    print(f"Salt: {salt}")

    # Example usage of execute_command_safely
    try:
        # This is a safe example because the command is statically defined.
        output = execute_command_safely(["ls", "-l"])
        if output:
            print(f"Command output:\n{output}")

        # This is a *potentially dangerous* example.  Use with extreme caution.
        # It's better to avoid constructing commands from user input if possible.
        user_input = "hello world"
        safe_command = construct_command_from_input(user_input)
        output2 = execute_command_safely(safe_command)
        if output2:
            print(f"Command output (from user input):\n{output2}")

    except Exception as e:
        print(f"Error during command execution: {e}")

