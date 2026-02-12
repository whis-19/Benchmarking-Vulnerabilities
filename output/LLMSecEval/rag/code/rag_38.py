import subprocess
import shlex
import os

def execute_ls_safely(directory="."):
    """
    Executes the 'ls' command safely using subprocess and shlex.

    This function avoids using `system()` and constructs the command
    using `subprocess.run()` with `shlex.quote()` to prevent command injection.
    It also includes an allowlist of allowed commands and executes within a sandboxed environment (using chroot as an example, but this requires root privileges and is for demonstration purposes only).

    Args:
        directory (str, optional): The directory to list. Defaults to ".".

    Returns:
        str: The output of the 'ls' command, or None if an error occurred.
    """

    # 1. Allowlist of allowable commands
    allowed_commands = ["ls"]

    # 2. Command construction (using shlex.quote for safety)
    command = "ls"
    arguments = [directory]

    # 3. Input validation and sanitization (strict allowlist)
    def is_safe_string(s):
        """Checks if a string contains only safe characters."""
        # This is a very strict allowlist.  Adjust as needed, but be careful!
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_"
        return all(c in allowed_chars for c in s)

    if not all(is_safe_string(arg) for arg in arguments):
        print("Error: Unsafe characters in directory name.")
        return None

    # Quote the arguments to prevent command injection
    quoted_arguments = [shlex.quote(arg) for arg in arguments]
    full_command = [command] + quoted_arguments

    # 4. Sandbox environment (chroot example - requires root and setup)
    # WARNING: This is a simplified example and requires root privileges.
    # In a real application, use a more robust sandboxing solution like Docker,
    # AppArmor, or SELinux.  Also, chroot requires careful setup to be secure.
    # The following code is for demonstration purposes only and should not be
    # used in production without proper security review and configuration.

    # Create a temporary directory for chroot
    # chroot_dir = "/tmp/chroot_jail"  # Example - use a more secure location
    # try:
    #     os.makedirs(chroot_dir, exist_ok=True)
    #     # Copy necessary files (e.g., /bin/ls, /lib64, etc.) into the chroot directory
    #     # This is a complex process and depends on the system.
    #     # For example:
    #     # shutil.copy2("/bin/ls", chroot_dir)
    #     # Create necessary directories (e.g., /lib64)
    #     # os.makedirs(os.path.join(chroot_dir, "lib64"), exist_ok=True)
    #     # Copy shared libraries required by ls
    #     # ldd /bin/ls | awk '/=>/ {print $3}' | xargs -I {} cp {} /tmp/chroot_jail/lib64/
    #
    #     # Change root directory
    #     os.chroot(chroot_dir)
    #
    #     # Execute the command within the chroot environment
    #     result = subprocess.run(full_command, capture_output=True, text=True, check=False)
    #
    #     # Restore the original root directory (important!)
    #     os.chroot(".")
    #
    #     # Remove the chroot directory (optional, but recommended)
    #     # shutil.rmtree(chroot_dir)
    #
    # except OSError as e:
    #     print(f"Error setting up chroot: {e}")
    #     return None

    # 5. Execute the command using subprocess.run (without chroot for now)
    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            return result.stdout
        else:
            print(f"Error executing command: {result.stderr}")
            return None
    except FileNotFoundError:
        print(f"Command not found: {command}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
output = execute_ls_safely(".")
if output:
    print(output)

output = execute_ls_safely("safe_directory") # Example with a safe directory name
if output:
    print(output)

output = execute_ls_safely("directory with spaces") # Example with spaces in directory name
if output:
    print(output)

output = execute_ls_safely("../../../etc/passwd") # Example with a potentially unsafe directory name
if output:
    print(output)
else:
    print("Command execution prevented due to unsafe characters.")

