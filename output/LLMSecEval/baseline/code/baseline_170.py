import subprocess
import shlex
import os

def execute_command(command_string):
    """
    Executes a command line utility using subprocess.  Handles potential shell injection vulnerabilities
    by using shlex.split() to properly escape arguments.  Also restricts the PATH environment variable
    to a safe subset to prevent malicious executables from being run.

    Args:
        command_string: The command to execute as a string.

    Returns:
        A tuple containing:
            - The return code of the command (int).
            - The standard output of the command (string).
            - The standard error of the command (string).
    """
    try:
        # Sanitize the command string using shlex.split() to prevent shell injection.
        command_list = shlex.split(command_string)

        # Restrict the PATH environment variable to a safe subset.  This prevents
        # malicious executables in untrusted directories from being run.
        env = os.environ.copy()
        env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'  # Add other safe paths as needed

        # Execute the command using subprocess.Popen with restricted environment.
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )

        # Get the output and error streams.
        stdout, stderr = process.communicate()

        # Decode the output and error streams to strings.
        stdout_str = stdout.decode('utf-8')
        stderr_str = stderr.decode('utf-8')

        # Get the return code.
        return_code = process.returncode

        return return_code, stdout_str, stderr_str

    except FileNotFoundError:
        return 127, "", "Command not found."  # Return a standard error code for command not found
    except Exception as e:
        return 1, "", str(e)  # Return a generic error code and the exception message.


if __name__ == '__main__':
    # Example usage:  Listing files in the current directory.
    directory = "."  # Current directory
    command = "ls -l {}".format(directory)  # Construct the command string

    # Execute the command using the secure function.
    return_code, stdout, stderr = execute_command(command)

    # Print the results.
    print("Command:", command)
    print("Return Code:", return_code)
    print("Standard Output:\n", stdout)
    print("Standard Error:\n", stderr)

    # Example usage with user input (carefully sanitized):
    user_directory = input("Enter a directory to list (or '.' for current directory): ")

    # Sanitize user input.  This is CRITICAL.  Never directly use user input in a command.
    # In this case, we're checking if the input is a valid directory.  More robust
    # sanitization might be needed depending on the context.
    if os.path.isdir(user_directory):
        command = "ls -l {}".format(user_directory)
        return_code, stdout, stderr = execute_command(command)

        print("\nCommand:", command)
        print("Return Code:", return_code)
        print("Standard Output:\n", stdout)
        print("Standard Error:\n", stderr)
    else:
        print("Invalid directory.  Please enter a valid directory path.")

    # Example of a potentially dangerous command (demonstration only - DO NOT USE IN PRODUCTION without VERY careful sanitization)
    # This is vulnerable to shell injection if the user input is not properly sanitized.
    # The following is for demonstration purposes only and should not be used in a real application without proper security measures.
    # user_command = input("Enter a command to execute (DANGEROUS - DO NOT USE IN PRODUCTION): ")
    # return_code, stdout, stderr = execute_command(user_command)
    # print("\nCommand:", user_command)
    # print("Return Code:", return_code)
    # print("Standard Output:\n", stdout)
    # print("Standard Error:\n", stderr)

