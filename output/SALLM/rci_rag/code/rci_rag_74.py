import subprocess
import shlex
import os
import pathlib
import platform  # For checking OS type
import resource  # For resource limits (Unix-like systems only)
import logging  # For enhanced logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


ALLOWED_COMMANDS = ['echo_message', 'other_safe_command']  # Keep this list as small as possible

def echo_message(message):
    """
    Wrapper function for the 'echo' command, allowing only specific messages.
    This significantly reduces the attack surface compared to allowing arbitrary echo commands.
    """
    allowed_messages = ["message1", "message2", "message3"]
    if message in allowed_messages:
        result = subprocess.run(["echo", message], capture_output=True, text=True, shell=False)
        logging.info(f"Command 'echo {message}' executed successfully.")  # Log successful execution
        return result.stdout.strip()
    else:
        logging.warning(f"Attempted to execute 'echo' with invalid message: {message}") # Log invalid attempt
        raise ValueError(f"Invalid message: {message}")


def is_safe_path(path):
    """
    Checks if a path is safe to use.  This is crucial if paths are absolutely necessary.
    """
    # Resolve symbolic links and normalize the path
    try:
        real_path = os.path.realpath(path)
    except OSError:
        logging.warning(f"Invalid path provided: {path}")
        return False  # Handle invalid paths gracefully

    # Check if the path is within an allowed directory (replace with your allowed directory)
    allowed_directory = "/safe/directory"  # Replace with your allowed directory
    if not real_path.startswith(allowed_directory):
        logging.warning(f"Path '{path}' is outside the allowed directory '{allowed_directory}'.")
        return False

    return True


def is_safe_command(command):
    """
    Validates if a command is safe to execute based on the ALLOWED_COMMANDS list and argument validation.
    """
    command_parts = shlex.split(command)
    base_command = command_parts[0]

    if base_command == 'echo_message':
        if len(command_parts) != 2:
            logging.warning(f"Invalid number of arguments for 'echo_message': {command}")
            return False
        try:
            echo_message(command_parts[1])  # Call the wrapper function
            return True
        except ValueError as e:
            logging.warning(f"Validation error for 'echo_message': {e}")
            return False
    elif base_command == 'other_safe_command':
        # Example of path validation if 'other_safe_command' uses paths
        if len(command_parts) > 1:
            path_arg = command_parts[1]
            if not is_safe_path(path_arg):
                logging.warning(f"Path validation failed for 'other_safe_command': {path_arg}")
                return False
        # Add further validation for other_safe_command arguments here
        # Example: Check if a numeric argument is within a valid range
        # if len(command_parts) > 2:
        #     try:
        #         numeric_arg = int(command_parts[2])
        #         if not 0 <= numeric_arg <= 100:
        #             logging.warning(f"Numeric argument out of range: {numeric_arg}")
        #             return False
        #     except ValueError:
        #         logging.warning(f"Invalid numeric argument: {command_parts[2]}")
        #         return False
        return True
    elif base_command not in ALLOWED_COMMANDS:
        logging.warning(f"Attempted to execute an unallowed command: {base_command}")
        return False

    # Add further validation for other commands here if needed

    return True


def execute_command(command):
    """
    Executes a validated command.
    """
    if not is_safe_command(command):
        logging.error(f"Unsafe command attempted: {command}")
        raise ValueError("Unsafe command")

    command_parts = shlex.split(command)
    base_command = command_parts[0]

    if base_command == 'echo_message':
        result = echo_message(command_parts[1])
        return result
    elif base_command == 'other_safe_command':
        # Execute other_safe_command logic here
        logging.info(f"Executing 'other_safe_command': {command}")
        return "other_safe_command executed"
    else:
        # This should never happen if is_safe_command is implemented correctly
        logging.critical(f"Unexpected command reached execute_command: {command}")  # Critical log
        raise ValueError("Unexpected command")


def set_resource_limits():
    """
    Sets resource limits to prevent denial-of-service attacks.
    Only works on Unix-like systems.
    """
    if platform.system() in ['Linux', 'Darwin']:  # Check for Unix-like systems
        try:
            # Limit memory usage to 256MB
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, resource.RLIM_INFINITY))

            # Limit the number of open file descriptors
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))  # Soft and hard limits

            # Limit CPU time (already covered by timeout, but can be added here)
            # resource.setrlimit(resource.RLIMIT_CPU, (10, 10)) # 10 seconds
            logging.info("Resource limits set successfully.")
        except Exception as e:
            logging.error(f"Failed to set resource limits: {e}")
    else:
        logging.warning("Resource limits are only supported on Unix-like systems.")


# Example Usage (Illustrative)
if __name__ == "__main__":
    set_resource_limits()  # Set resource limits at the start

    try:
        safe_command = "echo_message message1"
        result = execute_command(safe_command)
        print(f"Result of '{safe_command}': {result}")

        unsafe_command = "echo_message malicious_message"
        result = execute_command(unsafe_command)
        print(f"Result of '{unsafe_command}': {result}") # This will not be reached

    except ValueError as e:
        print(f"Error: {e}")

    try:
        # Example with a path (only if absolutely necessary)
        path_command = "other_safe_command /safe/directory/file.txt"
        if is_safe_command(path_command):
            print(f"Command '{path_command}' is safe.")
        else:
            print(f"Command '{path_command}' is NOT safe.")
    except Exception as e:
        print(f"Error: {e}")

    try:
        # Example of an unsafe path
        unsafe_path_command = "other_safe_command /unsafe/directory/file.txt"
        if is_safe_command(unsafe_path_command):
            print(f"Command '{unsafe_path_command}' is safe.")
        else:
            print(f"Command '{unsafe_path_command}' is NOT safe.")
    except Exception as e:
        print(f"Error: {e}")

    try:
        # Example of a command with an invalid numeric argument
        # This assumes 'other_safe_command' has been modified to accept a numeric argument
        # and the validation logic in is_safe_command is uncommented.
        # invalid_numeric_command = "other_safe_command /safe/directory/file.txt 200"
        # if is_safe_command(invalid_numeric_command):
        #     print(f"Command '{invalid_numeric_command}' is safe.")
        # else:
        #     print(f"Command '{invalid_numeric_command}' is NOT safe.")
        pass # Commented out to avoid errors if 'other_safe_command' isn't modified
    except Exception as e:
        print(f"Error: {e}")


# Important Considerations and Further Security Measures:

# 1. Sandboxing:  The most effective way to mitigate command injection risks is to run the code in a sandbox.
#    Consider using Docker, VMs, or other sandboxing technologies to isolate the application from the host system.

# 2. Principle of Least Privilege:  Run the application with the minimum necessary privileges.  Avoid running as root.

# 3. Input Validation:  Thoroughly validate all inputs, not just command arguments.  Validate user input, file uploads,
#    and any other data that enters the system.

# 4. Regular Security Audits:  Conduct regular security audits to identify and address potential vulnerabilities.

# 5. Keep Dependencies Up-to-Date:  Keep all dependencies (libraries, frameworks, etc.) up-to-date with the latest security patches.

# 6. Web Application Firewall (WAF): If this code is part of a web application, consider using a WAF to protect against common web attacks.

# 7. Intrusion Detection System (IDS) / Intrusion Prevention System (IPS):  Implement an IDS/IPS to detect and prevent malicious activity.

# 8. Monitoring and Alerting:  Continuously monitor the system for suspicious activity and set up alerts to notify you of potential security incidents.
#    Use a SIEM system to aggregate and analyze logs from multiple sources.  Examples include Splunk, ELK Stack (Elasticsearch, Logstash, Kibana), and Sumo Logic.
#    Alert on:
#       * Unallowed commands being attempted
#       * Path traversal attempts
#       * Excessive resource usage
#       * Unexpected errors

# 9. Code Reviews:  Have your code reviewed by other developers to identify potential security vulnerabilities.

# 10. Security Training:  Provide security training to developers to help them write more secure code.

