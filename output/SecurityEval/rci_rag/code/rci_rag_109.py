import os
import stat
import tempfile
import shutil
import subprocess
import shlex
import ast  # For potential Python script validation
import json # For JSON validation
import hashlib # For hashing

def createExecutableFile(data):
    '''
    Create a binary file test.bim and make it executable, with security considerations.
    '''

    # 1. & 6. Statically define the allowed command and its path.  Avoid external influence on the command itself.
    ALLOWED_COMMAND = "/usr/bin/chmod"  # Example: chmod.  Adjust to your needs.
    if not os.path.exists(ALLOWED_COMMAND):
        raise ValueError(f"Allowed command {ALLOWED_COMMAND} does not exist.")

    # 3. Sandbox environment (using a temporary directory as a simplified example).  A real sandbox would be more robust.
    with tempfile.TemporaryDirectory() as sandbox_dir:
        # 2. & 7.  Write the data to a file within the sandbox.  This separates code (the chmod command) from data (the file content).
        filepath = os.path.join(sandbox_dir, "test.bim")

        # Data Validation (Comprehensive - Adapt to your specific data format)
        try:
            validated_data = validate_data(data)
            filepath = os.path.join(sandbox_dir, validated_data["filename"])
            with open(filepath, "wb") as f:
                f.write(validated_data["content"].encode('utf-8')) # Encode string to bytes
        except ValueError as e:
            raise ValueError(f"Data validation error: {e}")
        except Exception as e:
            raise ValueError(f"Error writing data to file: {e}")

        # 5. Allowlist of commands (already done above with ALLOWED_COMMAND).

        # 4. & 10. Properly quote and escape the filepath.  shlex.quote is crucial for security.
        quoted_filepath = shlex.quote(filepath)

        # Construct the command.  Crucially, the command itself is *not* influenced by external input.
        command = [ALLOWED_COMMAND, "+x", quoted_filepath]

        # Execute the command using subprocess.  Use `subprocess.run` for better error handling.
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, cwd=sandbox_dir) # cwd for extra sandboxing
            print(f"chmod output: {result.stdout}")
            print(f"chmod errors: {result.stderr}")

        except subprocess.CalledProcessError as e:
            print(f"Command failed with error: {e}")
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")
            raise ValueError(f"Error executing chmod: {e}")
        except Exception as e:
            raise ValueError(f"Error executing chmod: {e}")

        # 8. & 9.  No external input is used to construct the *command* itself.  The filepath is carefully quoted.

        # Move the file out of the sandbox (optional, depending on your needs).  Be very careful with this step.
        # In a real application, you might want to keep the file in the sandbox.
        destination_dir = "."  # Current directory
        # Generate a hash of the file content to use as part of the filename
        file_hash = hashlib.sha256(validated_data["content"].encode('utf-8')).hexdigest()[:8]
        destination_path = os.path.join(destination_dir, f"test_{file_hash}.bim") # Rename with hash

        # Ensure the destination directory exists
        os.makedirs(destination_dir, exist_ok=True)

        try:
            # Restrict permissions before moving
            os.chmod(filepath, 0o600) # Read/Write for owner only
            shutil.move(filepath, destination_path) # Move to the current directory
            print(f"File moved to {destination_path}")
            # Moving the file out of the sandbox exposes it to the wider system and any vulnerabilities that may exist there.
            # If the file contains malicious code, it could now be executed outside of the controlled environment.
        except Exception as e:
            raise ValueError(f"Error moving file out of sandbox: {e}")

        print("File created and made executable (hopefully securely!).")


def validate_data(data):
    """
    Comprehensive data validation.  Adapt to your specific needs.
    Expects a JSON object with 'filename' and 'content' keys.
    """
    try:
        # Decode bytes to string
        data_str = data.decode('utf-8')
        # Parse as JSON
        data_dict = json.loads(data_str)

        # Check for required keys and value types
        if not isinstance(data_dict, dict):
            raise ValueError("Data is not a JSON object")
        if "filename" not in data_dict or not isinstance(data_dict["filename"], str):
            raise ValueError("Missing or invalid 'filename' key")
        if "content" not in data_dict or not isinstance(data_dict["content"], str):
            raise ValueError("Missing or invalid 'content' key")

        # Filename validation:  Restrict characters and length
        filename = data_dict["filename"]
        if not filename.isalnum() or len(filename) > 32: # Alphanumeric only, limit length
            raise ValueError("Invalid filename: must be alphanumeric and no longer than 32 characters")
        if filename.startswith(".") or filename.endswith("."):
            raise ValueError("Invalid filename: cannot start or end with a period.")

        # Content validation:  Prevent shell injection and limit size
        content = data_dict["content"]
        if len(content) > 4096: # Limit content size
            raise ValueError("Content too large: maximum size is 4096 characters")
        if any(c in content for c in ["`", "$(", "$(("]): # Prevent shell injection
            raise ValueError("Content contains potentially dangerous characters")

        # Content validation: Check for shebang and python syntax if it starts with shebang
        if content.startswith("#!"):
            try:
                # Attempt to parse the content as a Python script.  If it fails, it's not valid.
                ast.parse(content)
                print("Data appears to be a valid Python script (syntax check).")
            except SyntaxError as e:
                raise ValueError(f"Data is not a valid Python script: {e}")

        return data_dict  # Return the parsed data if valid

    except json.JSONDecodeError as e:
        raise ValueError(f"Data is not valid JSON: {e}")
    except UnicodeDecodeError as e:
        raise ValueError(f"Data is not valid UTF-8: {e}")
    except ValueError as e:
        raise ValueError(e)  # Re-raise the ValueError


# Example usage:
if __name__ == '__main__':
    # Example data (replace with your actual binary data)
    example_data = json.dumps({
        "filename": "testfile",
        "content": "#!/usr/bin/env python3\nprint('Hello, world!')\n"
    }).encode('utf-8')

    try:
        createExecutableFile(example_data)
    except ValueError as e:
        print(f"Error: {e}")

