import os
import stat
import secrets
import subprocess
import shlex

def create_and_secure_file(filename="secret.txt", content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file, writes content to it, restricts permissions, and prints the permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "U2FsdGVkX1/R+WzJcxgvX/Iw==".
    """

    try:
        # Create the file and write the content
        with open(filename, "w") as f:
            f.write(content)

        # Restrict permissions to owner read/write only (0600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

        # Get and print the file permissions using a safe method
        # Using stat.filemode to get a human-readable representation
        st = os.stat(filename)
        permissions = stat.filemode(st.st_mode)
        print(f"Permissions of {filename}: {permissions}")

    except OSError as e:
        print(f"Error: Could not create or modify file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def create_and_secure_file_sandboxed(filename="secret.txt", content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file, writes content to it, restricts permissions, and prints the permissions,
    attempting to use a sandbox (chroot) for added security.  This requires root privileges
    and a properly configured chroot environment.  This is a simplified example and
    a full chroot setup is beyond the scope of this code.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "U2FsdGVkX1/R+WzJcxgvX/Iw==".
    """

    # This is a placeholder for a real chroot environment.  In a real application,
    # you would need to create a chroot directory and copy all necessary files
    # (including Python interpreter and libraries) into it.

    # For demonstration purposes, we'll just check if we're running as root.
    if os.geteuid() != 0:
        print("Warning: Running this function requires root privileges to use chroot effectively.")
        create_and_secure_file(filename, content) # Fallback to non-sandboxed version
        return

    try:
        # Create a temporary directory to act as a simplified "chroot"
        temp_chroot = "/tmp/temp_chroot_" + secrets.token_hex(8)
        os.makedirs(temp_chroot, exist_ok=False)

        # Construct the command to execute within the "chroot"
        # We're using a safe way to construct the command using shlex.quote to prevent injection
        # This example assumes python3 is available in the chroot environment.  In a real
        # chroot, you'd need to copy the python interpreter and necessary libraries.
        python_code = f"""
import os
import stat

filename = '{filename}'
content = '{content}'

try:
    with open(filename, "w") as f:
        f.write(content)

    os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    st = os.stat(filename)
    permissions = stat.filemode(st.st_mode)
    print(f"Permissions of {{filename}}: {{permissions}}")

except OSError as e:
    print(f"Error: Could not create or modify file: {{e}}")
except Exception as e:
    print(f"An unexpected error occurred: {{e}}")
"""

        # Use shlex.quote to safely embed the python code into the command
        quoted_python_code = shlex.quote(python_code)
        command = f"chroot {shlex.quote(temp_chroot)} python3 -c {quoted_python_code}"

        # Execute the command using subprocess.run with shell=True (carefully!)
        # Because we've used shlex.quote, this is considered safer than directly
        # constructing the command string.  However, shell=True should still be
        # used with caution.
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            print("File created and secured within the (simulated) chroot environment.")
            print(result.stdout)
        else:
            print(f"Error executing command within chroot: {result.stderr}")

    except OSError as e:
        print(f"Error: Could not create temporary chroot directory: {e}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Clean up the temporary chroot directory (remove it and its contents)
        try:
            # Use a safer method to remove the directory and its contents
            subprocess.run(["rm", "-rf", temp_chroot], check=False)
        except Exception as e:
            print(f"Warning: Could not clean up temporary chroot directory: {e}")


# Example usage:
# create_and_secure_file()
create_and_secure_file_sandboxed()

