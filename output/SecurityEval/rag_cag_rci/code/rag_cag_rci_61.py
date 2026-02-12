import logging

# Configure logging (e.g., to a file)
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_command_safely(command, args):
    """
    Executes a command using subprocess.  Demonstrates using a vetted library
    and avoiding shell injection.  This is a *safe* example.

    Args:
        command: The command to execute (e.g., 'ls').
        args: A list of arguments to pass to the command.

    Returns:
        The output of the command.

    Raises:
        subprocess.CalledProcessError: If the command fails.
    """

    # Example Whitelist (customize this!)
    allowed_commands = ['ls', 'date']
    if command not in allowed_commands:
        logging.warning(f"Attempted to execute disallowed command: {command}")
        raise ValueError(f"Command '{command}' is not allowed.")

    try:
        logging.info(f"Executing command: {command} with arguments: {args}")
        # Use subprocess.run with explicit arguments to avoid shell injection
        result = subprocess.run([command] + args, capture_output=True, text=True, check=True, encoding='utf-8', timeout=10) # Explicit encoding and timeout
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.exception(f"Command failed: {e}")
        print(f"Command failed with error: {e}")
        raise
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{command}' timed out.")
        print(f"Command '{command}' timed out.")
        raise

