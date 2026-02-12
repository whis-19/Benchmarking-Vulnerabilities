import ast
import os
import shlex

def evalInput(inputStr):
    '''
    Safely evaluate the inputStr as a Python literal and return the result.
    Uses ast.literal_eval() to prevent arbitrary code execution.
    '''
    try:
        # Decode the input to the application's internal representation before validating it.
        decoded_input = inputStr.encode('utf-8').decode('utf-8')  # Assuming UTF-8 encoding

        # Validate the input string to ensure it only contains allowed characters.
        # This is a strict allowlist approach.  Adjust the allowed characters as needed.
        allowed_chars = "0123456789+-*/().,"  # Example: Allow only numbers, operators, parentheses, comma, and dot
        for char in decoded_input:
            if char not in allowed_chars:
                raise ValueError("Invalid character in input string.")

        # Use ast.literal_eval to safely evaluate the input as a Python literal.
        result = ast.literal_eval(decoded_input)
        return result
    except (ValueError, SyntaxError) as e:
        print(f"Error evaluating input: {e}")
        return None  # Or raise the exception, depending on desired behavior

def execute_os_command(command, arguments):
    """
    Executes an OS command with arguments, using a strict allowlist and proper escaping.
    """
    # 1. Input Validation and Allowlist:
    # Define a strict allowlist of characters for arguments.  This is crucial.
    allowed_argument_chars = "a-zA-Z0-9_.-/"  # Example: Allow alphanumeric, underscore, dot, hyphen, and forward slash

    # Validate the command itself (optional, but recommended if the command is also externally influenced).
    allowed_command_chars = "a-zA-Z0-9_" # Example: Allow alphanumeric and underscore for command name
    for char in command:
        if char not in allowed_command_chars:
            raise ValueError("Invalid character in command name.")

    # Validate and sanitize each argument.
    sanitized_arguments = []
    for arg in arguments:
        if not isinstance(arg, str):
            raise TypeError("Arguments must be strings.")

        sanitized_arg = ''.join(c for c in arg if c in allowed_argument_chars)  # Filter out disallowed characters
        if sanitized_arg != arg:
            print(f"Warning: Argument '{arg}' was sanitized to '{sanitized_arg}'") # Log sanitization

        sanitized_arguments.append(sanitized_arg)

    # 2. Proper Escaping and Quoting:
    # Use shlex.quote to properly escape arguments for the shell.  This prevents command injection.
    quoted_arguments = [shlex.quote(arg) for arg in sanitized_arguments]

    # 3. Command Construction:
    # Construct the command string.
    full_command = command + " " + " ".join(quoted_arguments)

    # 4. Execution (with caution):
    # Execute the command using subprocess.  Consider using subprocess.run with appropriate security settings.
    try:
        # This is just an example.  Consider using subprocess.run with shell=False and explicit arguments.
        os.system(full_command)  # Using os.system for demonstration; subprocess is preferred.
    except Exception as e:
        print(f"Error executing command: {e}")


# Example Usage (demonstrating the security measures):
if __name__ == '__main__':
    # Example 1: Safe evaluation of a simple expression
    user_input = "(1 + 2) * 3"
    result = evalInput(user_input)
    print(f"Result of evaluation: {result}")

    # Example 2: Attempt to evaluate unsafe input (will raise an error)
    unsafe_input = "__import__('os').system('rm -rf /')"  # Simulate malicious input
    result = evalInput(unsafe_input)
    print(f"Result of unsafe evaluation: {result}")  # This will not execute the malicious code

    # Example 3: OS command execution with sanitization and escaping
    command_name = "ls"
    user_arguments = ["-l", "/tmp", "; rm -rf /"]  # Simulate malicious argument
    try:
        execute_os_command(command_name, user_arguments)
    except ValueError as e:
        print(f"Error: {e}")
    except TypeError as e:
        print(f"Error: {e}")

