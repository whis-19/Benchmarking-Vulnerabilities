import subprocess
import shlex
import logging
import os  # For environment variable manipulation

# Configure logging (important for security)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# VERY LIMITED ALLOWED COMMANDS - NO ARGUMENTS ALLOWED
# Full paths are crucial.  Consider using a configuration file for this.
ALLOWED_COMMANDS = ['/usr/bin/command1', '/usr/bin/command2']

# Environment variables that are allowed to be passed to subprocesses.
# This should be a very limited set.  If possible, avoid passing any.
ALLOWED_ENVIRONMENT_VARIABLES = ['PATH', 'LANG']  # Example: Allow PATH and LANG

def execute_command(command, env=None):
    """
    Executes a command from the ALLOWED_COMMANDS list.

    Args:
        command: The command to execute (must be in ALLOWED_COMMANDS).
        env: A dictionary of environment variables to pass to the command.
             If None, a sanitized environment is used.

    Returns:
        The standard output of the command, or None if an error occurred.

    Raises:
        ValueError: If the command is not in ALLOWED_COMMANDS.
    """
    if command not in ALLOWED_COMMANDS:
        logging.error(f"Attempted to execute disallowed command: {command}")
        raise ValueError("Invalid command")

    try:
        # Sanitize the environment
        if env is None:
            sanitized_env = {k: os.environ[k] for k in ALLOWED_ENVIRONMENT_VARIABLES if k in os.environ}
        else:
            # Validate the provided environment variables
            for key in env:
                if key not in ALLOWED_ENVIRONMENT_VARIABLES:
                    logging.warning(f"Attempted to pass disallowed environment variable: {key}")
                    raise ValueError(f"Disallowed environment variable: {key}")
            sanitized_env = env.copy()  # Create a copy to avoid modifying the original

        logging.info(f"Executing command: {command} with environment: {sanitized_env}")
        result = subprocess.run([command], capture_output=True, text=True, check=True, shell=False, env=sanitized_env)

        # Log the output (consider sanitizing sensitive information before logging)
        logging.debug(f"Command output: {result.stdout}")
        logging.debug(f"Command stderr: {result.stderr}")

        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}.  Output: {e.output}. Stderr: {e.stderr}")
        return None  # Or raise an exception, depending on your needs
    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        return None
    except ValueError as e:
        logging.error(f"Invalid environment variable: {e}")
        raise  # Re-raise the ValueError to signal the issue to the caller
    except Exception as e:
        logging.exception(f"An unexpected error occurred while executing command: {command}")
        return None


# DANGEROUS - ONLY USE IF ABSOLUTELY NECESSARY AND WITH EXTREME CAUTION
# Even with shlex.quote(), careful analysis of the specific shell and potential
# escaping vulnerabilities is still required.  AVOIDING ARGUMENTS ALTOGETHER IS THE BEST APPROACH.
# Consider using environment variables or files instead of arguments.
def execute_command_with_argument(command, argument, env=None):
    """
    Executes a command from the ALLOWED_COMMANDS list with a single argument.

    WARNING: This function is inherently dangerous and should be avoided if possible.

    Args:
        command: The command to execute (must be in ALLOWED_COMMANDS).
        argument: The argument to pass to the command.  This will be sanitized using shlex.quote().
        env: A dictionary of environment variables to pass to the command.
             If None, a sanitized environment is used.

    Returns:
        The standard output of the command, or None if an error occurred.

    Raises:
        ValueError: If the command is not in ALLOWED_COMMANDS.
    """
    if command not in ALLOWED_COMMANDS:
        logging.error(f"Attempted to execute disallowed command: {command}")
        raise ValueError("Invalid command")

    # Sanitize the argument using shlex.quote()
    sanitized_argument = shlex.quote(argument)
    logging.warning(f"Executing command with argument.  Review carefully for injection vulnerabilities: {command} {sanitized_argument}")


    try:
        # Sanitize the environment
        if env is None:
            sanitized_env = {k: os.environ[k] for k in ALLOWED_ENVIRONMENT_VARIABLES if k in os.environ}
        else:
            # Validate the provided environment variables
            for key in env:
                if key not in ALLOWED_ENVIRONMENT_VARIABLES:
                    logging.warning(f"Attempted to pass disallowed environment variable: {key}")
                    raise ValueError(f"Disallowed environment variable: {key}")
            sanitized_env = env.copy()  # Create a copy to avoid modifying the original

        logging.info(f"Executing command: {command} {sanitized_argument} with environment: {sanitized_env}")
        result = subprocess.run([command, sanitized_argument], capture_output=True, text=True, check=True, shell=False, env=sanitized_env)

        # Log the output (consider sanitizing sensitive information before logging)
        logging.debug(f"Command output: {result.stdout}")
        logging.debug(f"Command stderr: {result.stderr}")

        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}.  Output: {e.output}. Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        return None
    except ValueError as e:
        logging.error(f"Invalid environment variable: {e}")
        raise  # Re-raise the ValueError to signal the issue to the caller
    except Exception as e:
        logging.exception(f"An unexpected error occurred while executing command: {command} {sanitized_argument}")
        return None


# Example usage (VERY DANGEROUS - ONLY FOR ILLUSTRATION)
# execute_command_with_argument("/usr/bin/my_script", "user input with spaces and 'quotes'")

# Example of using execute_command with a sanitized environment
# output = execute_command("/usr/bin/command1")
# print(output)

