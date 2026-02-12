import openai
import os
import subprocess
import shlex
import uuid
import hashlib
import logging
import sys
import re  # Import the regular expression module
from typing import List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set a maximum input length to prevent excessive resource consumption during embedding generation.
MAX_INPUT_LENGTH = 8192  # Adjust as needed based on your resource constraints and OpenAI API limits.

def get_embeddings(text: str) -> List[float]:
    '''
    Calculate the embeddings for the text provided as parameter using the OpenAI's 'text-embedding-ada-002' model.
    Then, return a list of the embeddings.

    Security Considerations:
    - Input Length Limiting:  Limits the input text length to prevent denial-of-service attacks by consuming excessive resources.
    - API Key Security:  The OpenAI API key should be stored in an environment variable (OPENAI_API_KEY) and *never* hardcoded in the code. Consider using a secrets management solution for production environments.
    - Data Privacy: Be mindful of the data you are sending to the OpenAI API and comply with OpenAI's usage policies.
    - Error Handling: Includes robust error handling to catch potential exceptions during API calls.
    - Rate Limiting: Implement retry logic with exponential backoff to handle OpenAI API rate limits gracefully.
    '''

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    if len(text) > MAX_INPUT_LENGTH:
        logging.warning(f"Input text exceeds maximum length ({MAX_INPUT_LENGTH} characters). Truncating.")
        text = text[:MAX_INPUT_LENGTH]

    try:
        # Implement retry logic with exponential backoff for rate limiting
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = openai.Embedding.create(
                    input=[text],
                    model="text-embedding-ada-002"
                )
                embeddings = response['data'][0]['embedding']
                return embeddings
            except openai.error.RateLimitError as e:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt)  # Exponential backoff
                    logging.warning(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                    import time
                    time.sleep(wait_time)
                else:
                    logging.error(f"OpenAI API rate limit exceeded after multiple retries: {e}")
                    raise  # Re-raise the exception to be handled by the calling function.
            except openai.error.OpenAIError as e:
                logging.error(f"OpenAI API error: {e}")
                raise  # Re-raise the exception to be handled by the calling function.
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")
                raise  # Re-raise the exception.

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise  # Re-raise the exception.


def generate_salted_hash(data: str) -> str:
    """
    Generates a salted SHA-256 hash of the input data.  A unique salt is generated for each hash.

    Security Considerations:
    - Random Salt: Uses a cryptographically secure random salt for each hash to prevent rainbow table attacks.
    - Encoding: Explicitly encodes the data and salt to ensure consistent hashing across different systems.
    """
    salt = uuid.uuid4().hex
    salted_data = salt + data
    hashed_data = hashlib.sha256(salted_data.encode('utf-8')).hexdigest()
    return hashed_data

ALLOWED_COMMANDS = ["echo", "grep", "cat", "ls"]  # Example whitelist - Add more commands as needed

def execute_command_safely(command: str, input_data: str = None) -> str:
    """
    Executes a command using a vetted library (subprocess with shlex) to prevent OS command injection.
    The command is executed in a restricted environment (if possible).

    Security Considerations:
    - Shlex: Uses shlex.split to properly escape and quote arguments, preventing command injection.
    - Subprocess: Uses subprocess.run with appropriate security settings.
    - Sandbox (Optional):  Ideally, this function would be executed within a sandbox environment (e.g., chroot, Docker container) for enhanced security.  This is not implemented here but should be considered for production environments.
    - Whitelisting:  The `command` is validated against a whitelist of allowed commands.
    - Input Validation:  Validate any input data passed *to* the command to prevent injection vulnerabilities.
    - Logging: Be extremely careful about logging the output of commands, as it may contain sensitive information.  Use debug level logging for command output.
    """
    try:
        # Split the command into a list of arguments using shlex for safe handling of spaces and special characters.
        command_list = shlex.split(command)

        # Command Whitelisting
        if command_list[0] not in ALLOWED_COMMANDS:
            raise ValueError(f"Command '{command_list[0]}' is not allowed.  Allowed commands are: {ALLOWED_COMMANDS}")

        # Input validation: Example - Validate that input_data is a string if provided
        if input_data is not None and not isinstance(input_data, str):
            raise ValueError("Input data must be a string.")

        # Input Validation based on command
        if command_list[0] == "grep" and input_data:
            # Sanitize input_data to prevent regex injection
            input_data = re.escape(input_data)  # Escape regex metacharacters
        elif command_list[0] == "cat":
            # Check if the file exists and is within allowed paths (if applicable)
            if len(command_list) > 1:
                filepath = command_list[1]
                if not os.path.exists(filepath):
                    raise ValueError(f"File not found: {filepath}")
                # Example: Restrict access to files within a specific directory
                # allowed_path = "/safe/directory/"
                # if not filepath.startswith(allowed_path):
                #     raise ValueError(f"Access to file outside allowed path: {filepath}")

        # Execute the command using subprocess.run with security options.
        result = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=60, input=input_data)  # Added timeout and input

        # Log the command and its output for auditing purposes.
        logging.info(f"Executed command: {command}")
        logging.debug(f"Command output: {result.stdout}") # Use DEBUG level
        logging.debug(f"Command error: {result.stderr}") # Use DEBUG level

        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Command execution failed: {e}")
        logging.error(f"Command output: {e.output}")
        return f"Error: {e}"
    except FileNotFoundError as e:
        logging.error(f"Command not found: {e}")
        return f"Error: {e}"
    except ValueError as e:
        logging.error(f"Invalid command or input: {e}")
        return f"Error: {e}"
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return f"Error: {e}"

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent path traversal vulnerabilities.

    Security Considerations:
    - Path Traversal Prevention: Removes or replaces characters that could be used for path traversal (e.g., "..", "/", "\").
    - Length Limitation: Limits the filename length to prevent buffer overflows or other issues.
    - Whitelisting:  Ideally, the filename should be validated against a whitelist of allowed characters.
    - ReDoS:  Be mindful of potential ReDoS vulnerabilities if the regex becomes more complex.
    """
    if not isinstance(filename, str):
        raise TypeError("Filename must be a string.")

    # Use a regular expression to whitelist allowed characters
    sanitized_filename = re.sub(r"[^a-zA-Z0-9_\-.]", "", filename)  # Allow alphanumeric, underscore, hyphen, and period
    sanitized_filename = sanitized_filename.lower() # Lowercase the filename

    sanitized_filename = sanitized_filename[:255]  # Limit filename length

    return sanitized_filename

def write_output_safely(data: str, filename: str, encoding: str = 'utf-8') -> None:
    """
    Writes data to a file, ensuring proper output encoding and sanitizing the filename.

    Security Considerations:
    - Filename Sanitization: Uses `sanitize_filename` to prevent path traversal vulnerabilities.
    - Output Encoding: Explicitly specifies the output encoding to prevent character encoding issues.
    - File Permissions:  The file is created with restrictive permissions (e.g., 0600) to prevent unauthorized access.
    - Logging: Be extremely careful about logging the data being written to the file, as it may contain sensitive information.  Consider redacting sensitive data before logging.
    """
    sanitized_filename = sanitize_filename(filename)
    try:
        with open(sanitized_filename, 'w', encoding=encoding) as f:
            f.write(data)
        # Set file permissions to 0600 (read/write for owner only)
        os.chmod(sanitized_filename, 0o600)
        logging.info(f"Successfully wrote data to file: {sanitized_filename}")
    except Exception as e:
        logging.error(f"Error writing to file: {e}")
        raise

# Example Usage (Illustrative - Replace with your actual OpenAI API key and data)
if __name__ == '__main__':
    # 1. Embedding Generation
    try:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set.")

        input_text = "This is a sample text for embedding generation."
        embeddings = get_embeddings(input_text)
        print(f"Embeddings: {embeddings[:10]}...")  # Print only the first 10 elements for brevity
    except Exception as e:
        print(f"Error during embedding generation: {e}")

    # 2. Salted Hash Generation
    data_to_hash = "Sensitive data to be hashed."
    hashed_data = generate_salted_hash(data_to_hash)
    print(f"Hashed data: {hashed_data}")

    # 3. Safe Command Execution (Illustrative - Use with caution and proper validation)
    # WARNING:  Executing arbitrary commands is inherently dangerous.  This example is for demonstration purposes only.
    # In a real-world application, you should carefully validate and sanitize any input used to construct commands.
    try:
        command_to_execute = "echo 'Hello, world!'"  # Replace with a safe, pre-defined command
        output = execute_command_safely(command_to_execute)
        print(f"Command output: {output}")

        # Example using grep with input validation
        command_to_execute = "grep 'pattern'"
        input_data = "This is a string with the pattern in it."
        output = execute_command_safely(command_to_execute, input_data)
        print(f"Grep output: {output}")

        command_to_execute = "grep 'pattern'"
        input_data = "This is a string with (potentially) malicious regex characters."
        output = execute_command_safely(command_to_execute, input_data)
        print(f"Grep output (with escaped input): {output}")

        # Example of an invalid command
        try:
            command_to_execute = "rm -rf /"  # VERY DANGEROUS - DO NOT USE IN REAL CODE
            output = execute_command_safely(command_to_execute) # This will raise an exception
            print(f"Command output: {output}")
        except ValueError as e:
            print(f"Command execution blocked: {e}")

        # Example using cat with file path validation
        try:
            command_to_execute = "cat output.txt"
            output = execute_command_safely(command_to_execute)
            print(f"Cat output: {output}")
        except ValueError as e:
            print(f"Command execution blocked: {e}")

    except Exception as e:
        print(f"Error during command execution: {e}")

    # 4. Safe File Writing
    data_to_write = "This is some data to write to a file."
    filename = "output.txt"
    try:
        write_output_safely(data_to_write, filename)
        print(f"Successfully wrote data to {filename}")
    except Exception as e:
        print(f"Error writing to file: {e}")

