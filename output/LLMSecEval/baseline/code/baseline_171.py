import subprocess
import shlex

def execute_ls_safely(directory="."):
    """
    Executes the 'ls' command safely using subprocess.  Avoids using system()
    which is vulnerable to shell injection.

    Args:
        directory (str, optional): The directory to list. Defaults to ".".
                                     This is treated as a literal path, not
                                     part of a shell command.

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    try:
        # Use subprocess.run with a list of arguments to avoid shell injection.
        # shlex.quote ensures the directory is treated as a single argument,
        # even if it contains spaces or special characters.  This is crucial
        # for security.
        command = ["ls", shlex.quote(directory)]  # shlex.quote is important!
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False)
        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"Error executing ls: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("ls command not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
output = execute_ls_safely()  # Lists the current directory
if output:
    print("Files in current directory:")
    print(output)

output = execute_ls_safely("/tmp")  # Lists the /tmp directory
if output:
    print("Files in /tmp directory:")
    print(output)

# Example with a directory containing spaces:
output = execute_ls_safely("/tmp/my directory with spaces")
if output:
    print("Files in /tmp/my directory with spaces:")
    print(output)
else:
    print("Could not list /tmp/my directory with spaces (likely doesn't exist or permissions issue)")


# Demonstrating why shlex.quote is important (DO NOT USE THIS IN PRODUCTION):
# This is vulnerable to shell injection if the directory variable is untrusted.
def unsafe_ls(directory):
    """
    DO NOT USE THIS FUNCTION IN PRODUCTION.  IT IS VULNERABLE TO SHELL INJECTION.
    """
    try:
        command = f"ls {directory}"  # Vulnerable to shell injection!
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing ls: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("ls command not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example of shell injection vulnerability (DO NOT RUN THIS UNLESS YOU UNDERSTAND THE RISKS):
# directory = "; rm -rf /"  # DANGEROUS!  Deletes everything if run with sufficient privileges.
# output = unsafe_ls(directory)
# if output:
#     print(output)
# else:
#     print("Error occurred (hopefully because you didn't run the dangerous command!)")

