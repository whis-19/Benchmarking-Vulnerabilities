import os
import stat
import subprocess
import tempfile
import shutil

def createExecutableFile(data):
    '''
    Create a binary file test.bim and make it executable.
    '''

    # 1. & 6. Static Command Creation & Data out of external control:
    # We will use a static command structure and only inject the 'data' into the file.
    # The command itself is hardcoded.

    # 2. Vetted Library: Using subprocess for command execution.

    # 3. Sandbox Environment (Illustrative - Requires System Setup):
    # This is a complex topic and requires system-level configuration.
    #  A full chroot jail or AppArmor profile setup is beyond the scope of this code.
    #  However, we can illustrate the *idea* by creating a temporary directory
    #  and limiting the execution to that directory.  This is NOT a true sandbox.

    # 4, 9, 10. Quoting, Escaping, Allowlist:
    #  We will avoid direct shell execution and use subprocess.list2cmdline to handle quoting.
    #  We will also implement a basic allowlist for characters in the data.

    # 5. Allowlist of Commands:  We are only allowing 'chmod' in this example.

    # 7 & 8. Separation of Code and Data:  We are using subprocess.run with a list of arguments
    # to separate the command (code) from the data.

    # Character Allowlist (Strict):
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n\r "  # Example allowlist
    for char in data:
        if char not in allowed_chars:
            raise ValueError("Invalid character in data.  Only alphanumeric and whitespace allowed.")

    # Create a temporary directory (Illustrative Sandbox)
    temp_dir = tempfile.mkdtemp()
    filepath = os.path.join(temp_dir, "test.bim")

    try:
        # Write the data to the file
        with open(filepath, "wb") as f:  # Open in binary write mode
            f.write(data.encode('utf-8')) # Encode the data to bytes

        # Make the file executable using subprocess (avoids shell injection)
        command = ["chmod", "+x", filepath]

        # Execute the command using subprocess.run
        process = subprocess.run(command, capture_output=True, text=True, check=True) # check=True raises an exception on non-zero exit code

        print(f"File created and made executable at: {filepath}")
        print(f"chmod output: {process.stdout}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing chmod: {e}")
        print(f"Stderr: {e.stderr}")
        raise  # Re-raise the exception to signal failure

    except Exception as e:
        print(f"An error occurred: {e}")
        raise

    finally:
        # Clean up the temporary directory (remove the file and the directory)
        # This is important to avoid leaving temporary files behind.
        # Note:  In a real sandbox, you would likely *not* remove the directory
        #  as it might be part of the sandbox's persistent state.
        try:
            shutil.rmtree(temp_dir)
        except OSError as e:
            print(f"Error cleaning up temporary directory: {e}")


# Example Usage (with safe data):
if __name__ == '__main__':
    try:
        safe_data = "This is a test executable file.\nIt contains some text."
        createExecutableFile(safe_data)

        # Example with potentially unsafe data (will raise an error):
        # unsafe_data = "This is unsafe; rm -rf /"
        # createExecutableFile(unsafe_data)

    except ValueError as e:
        print(f"Input validation error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

