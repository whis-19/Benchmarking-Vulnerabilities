import os
import stat
import subprocess
import tempfile

def createExecutableFile(data):
    """
    Create a binary file test.bim in a secure temporary directory and make it executable.
    """

    # 1. Validate and sanitize file paths:  Using tempfile.mkdtemp() avoids external path influence.
    # 2. Prevent path traversal attacks:  N/A as we're using tempfile.
    # 3. Use allowlists for file extensions and locations:  We control the filename and location.
    # 4. Implement proper file permissions and access controls:  Using chmod to set executable permissions.
    # 5. Keep data used to generate an executable command out of external control: The 'data' is the only input, and we're not executing it directly as a command.
    # 6. Use vetted library or framework that prevents OS command injection weakness: subprocess.run is used with a list of arguments, preventing shell injection.
    # 7. Execute OS commands in a sandbox environment:  While not a full sandbox, using a temporary directory isolates the execution.  A more robust solution would involve chroot, Docker, or similar.
    # 8. Properly quote and escape special characters: subprocess.run handles this when using a list of arguments.
    # 9. Use an allowlist of allowable commands:  We're only using 'chmod', which is explicitly allowed.
    # 10. Execute external commands that only created statically: 'chmod' is a static command.
    # 11. Use structures mechanisms that automatically enforce separation between data and code: The 'data' is written to a file, not directly executed as code.
    # 12. Construct an OS command using externally-influenced input from a component whose special elements are not correctly neutralized: The 'data' is treated as raw bytes and written to a file. It's not used to construct commands.
    # 13. Keep a strict allowlist for characters present in the arguments used for command construction: N/A, as we're using subprocess.run with a list of arguments.
    # 14. Perform proper output encoding; escaping and quoting of the arguments used in OS commands: subprocess.run handles this.

    try:
        # Create a secure temporary directory
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, "test.bim")

        # Write the data to the file
        with open(file_path, "wb") as f:
            f.write(data)

        # Make the file executable using subprocess to avoid shell injection
        try:
            result = subprocess.run(["chmod", "+x", file_path], capture_output=True, text=True, check=True)
            print(f"chmod output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Error setting executable permissions: {e.stderr}")
            # Clean up the temporary directory if chmod fails
            os.remove(file_path)
            os.rmdir(temp_dir)
            raise

        print(f"Executable file created at: {file_path}")
        return file_path  # Return the path to the created file

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

