import ast
import os
import shlex
import subprocess
import re
import unicodedata
import logging
import secrets
import configparser

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration from file
config = configparser.ConfigParser()
config.read('config.ini')

# Default values if config file is missing or incomplete
MAX_INPUT_LENGTH = int(config.get('evalInput', 'max_input_length', fallback=1024))
MAX_STRING_LENGTH = int(config.get('evalInput', 'max_string_length', fallback=256))
ALLOWED_COMMANDS = [cmd.strip() for cmd in config.get('execute_os_command', 'allowed_commands', fallback="ls,grep,cat,echo").split(',')]
MAX_DECODED_LENGTH = int(config.get('decode_and_validate', 'max_decoded_length', fallback=512))


def evalInput(inputStr):
    '''
    Safely evaluate the inputStr as a Python literal and return the result.
    Uses ast.literal_eval() to prevent arbitrary code execution.
    '''
    try:
        # Validate input length to prevent excessive resource consumption
        if len(inputStr) > MAX_INPUT_LENGTH:
            raise ValueError("Input string too long.")

        # Attempt to parse the input as a Python literal
        result = ast.literal_eval(inputStr)

        # Validate the type of the result.  Only allow specific types.
        allowed_types = (int, float, str, bool, list, tuple, dict, type(None))
        if not isinstance(result, allowed_types):
            raise ValueError("Input must evaluate to a simple literal (int, float, string, bool, list, tuple, dict, or None).")

        # Disallow complex numbers
        if isinstance(result, complex):
            raise ValueError("Complex numbers are not allowed.")

        # Further validation based on expected use case.  Example:
        if isinstance(result, str):
            # Validate string length
            if len(result) > MAX_STRING_LENGTH:
                raise ValueError("String input too long.")
            # Validate string content (e.g., only allow lowercase letters, numbers, and underscores)
            if not re.match("^[a-z0-9_]+$", result, re.ASCII):
                raise ValueError("String contains invalid characters.")

        return result
    except (ValueError, SyntaxError) as e:
        logging.error(f"Error evaluating input: {e}")
        raise  # Re-raise the exception

def execute_os_command(command, args):
    """
    Executes an OS command safely using shlex.quote and a strict allowlist.
    """
    # 1. Input Validation: Check command and arguments against an allowlist.
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{command}' is not allowed.")

    # 2. Argument Sanitization: Use shlex.quote for each argument.
    #    This prevents shell injection by properly escaping special characters.
    quoted_args = [shlex.quote(arg) for arg in args]

    # 3. Execute the command using subprocess.run (more secure than os.system).
    try:
        result = subprocess.run([command] + args, capture_output=True, check=True, text=True, shell=False) # text=True decodes output
        logging.info(f"Command output: {result.stdout}")
        logging.info(f"Command errors: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}")
        raise

def decode_and_validate(input_string, encoding="utf-8"):
    """
    Decodes an input string, validates it, and returns the decoded string.
    """
    try:
        # 1. Decode the input string to the application's internal representation.
        decoded_string = input_string.encode('latin-1', 'ignore').decode(encoding) # First encoding to remove invalid characters

        # 2. Normalize the decoded string to handle different Unicode representations.
        decoded_string = unicodedata.normalize('NFKC', decoded_string)

        # 3. Validate the decoded string.
        if not isinstance(decoded_string, str):
            raise ValueError("Decoded input is not a string.")

        if len(decoded_string) > MAX_DECODED_LENGTH:
            raise ValueError("Decoded string is too long.")

        # Example: Check for specific characters or patterns.
        if "<script>" in decoded_string:
            raise ValueError("Invalid characters in input.")

        # 4. Return the validated, decoded string.
        return decoded_string

    except UnicodeDecodeError as e:
        logging.error(f"Decoding error: {e}")
        raise ValueError("Invalid encoding.")
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        raise

# Example Usage (demonstrating the security measures):
if __name__ == '__main__':

    # Create a config.ini file if it doesn't exist
    if not os.path.exists('config.ini'):
        config['evalInput'] = {
            'max_input_length': 1024,
            'max_string_length': 256
        }
        config['execute_os_command'] = {
            'allowed_commands': 'ls,grep,cat,echo'
        }
        config['decode_and_validate'] = {
            'max_decoded_length': 512
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        print("Created default config.ini.  Please review and adjust as needed.")


    # Safe evaluation of literals:
    user_input = "{'name': 'Alice', 'age': 30}"
    try:
        data = evalInput(user_input)
        print(f"Parsed data: {data}")
    except ValueError as e:
        print(f"EvalInput Error: {e}")


    user_input_bad = "__import__('os').system('rm -rf /')" # Dangerous input
    try:
        data_bad = evalInput(user_input_bad) # This will not execute the dangerous code
    except ValueError as e:
        print(f"EvalInput Error: {e}")


    user_input_complex = "(1+1j)"
    try:
        data_complex = evalInput(user_input_complex) # This will raise an error because complex numbers are disallowed
    except ValueError as e:
        print(f"EvalInput Error: {e}")


    user_input_string = "valid_string123"
    try:
        data_string = evalInput(user_input_string)
        print(f"Parsed string: {data_string}")
    except ValueError as e:
        print(f"EvalInput Error: {e}")


    user_input_string_bad = "invalid String!"
    try:
        data_string_bad = evalInput(user_input_string_bad) # This will raise an error because of invalid characters
    except ValueError as e:
        print(f"EvalInput Error: {e}")


    # Safe OS command execution:
    try:
        execute_os_command("ls", ["-l", "/tmp"])
        # execute_os_command("rm", ["-rf", "/tmp/*"]) # This will raise an error because "rm" is not in the allowlist
    except ValueError as e:
        print(f"Command execution error: {e}")

    # Safe decoding and validation:
    try:
        encoded_input = "H\xe9llo world!".encode("utf-8")
        decoded_string = decode_and_validate(encoded_input.decode("utf-8"))
        print(f"Decoded string: {decoded_string}")
    except ValueError as e:
        print(f"Decoding/validation error: {e}")

    # Example of secrets.compare_digest (not directly used in the core functions, but demonstrating usage)
    secret_password = "my_secret_password"
    user_provided_password = "my_secret_password"  # Or from user input

    if secrets.compare_digest(secret_password, user_provided_password):
        print("Passwords match!")
    else:
        print("Passwords do not match.")

