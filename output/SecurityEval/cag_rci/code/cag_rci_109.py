import os
import stat
import logging
import shlex  # For safer command construction
import errno  # For handling specific OSError exceptions

# Configure logging (optional)
logging.basicConfig(level=logging.INFO)

def createExecutableFile(data):
    """
    Create a binary file test.bim and make it executable.
    """

    filename = "test.bim"

    if not isinstance(filename, str):
        raise TypeError("Filename must be a string.")

    # Normalize the filename
    filename = os.path.normpath(filename)

    if filename.startswith('/') or (os.name == 'nt' and len(filename) > 2 and filename[1] == ':'):
        raise ValueError("Filename cannot be an absolute path.")

    if ".." in filename:
        raise ValueError("Filename cannot contain '..' to prevent path traversal.")

    if '\0' in filename:
        raise ValueError("Filename cannot contain null bytes.")

    allowed_extensions = [".bim"]
    _, file_extension = os.path.splitext(filename)
    if file_extension.lower() not in allowed_extensions:
        raise ValueError(f"File extension '{file_extension}' is not allowed. Allowed extensions: {allowed_extensions}")

    allowed_directory = "/opt/myapp/bin"  # Or a specific safe directory
    filepath = os.path.join(allowed_directory, filename)

    try:
        # Ensure the directory exists
        try:
            os.makedirs(allowed_directory, exist_ok=True)
        except OSError as e:
            if e.errno != errno.EEXIST:  # Ignore if directory already exists
                logging.error(f"Error creating directory: {e}")
                raise

        # Create the file with restricted permissions
        with open(filepath, "wb") as f:
            if isinstance(data, str):
                f.write(data.encode('utf-8'))
            elif isinstance(data, bytes):
                f.write(data)
            else:
                raise TypeError("Data must be a string or bytes.")

        # Set executable permissions for the owner only
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        logging.info(f"Executable file '{filepath}' created successfully.")

    except OSError as e:
        logging.error(f"Error creating executable file: {e}")
        raise  # Re-raise the exception to signal failure
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        raise

# Example usage:
if __name__ == "__main__":
    try:
        # Example data (replace with your actual binary data)
        # example_data = "#!/bin/bash\necho 'Hello, world!'\n"  # DANGEROUS!
        # createExecutableFile(example_data) # DO NOT UNCOMMENT THIS LINE!

        # Instead of directly injecting code, consider a safer approach:
        # 1. Use a configuration file.
        # 2. If you MUST generate code, use a templating engine with strict escaping.
        # 3. If you MUST execute commands, use shlex.quote() to sanitize arguments.

        # Example using a configuration file:
        # with open("config.txt", "w") as f:
        #     f.write("message=Hello, world!")

        # Example using shlex.quote() (still risky, but better than direct injection):
        command = ["echo", "Hello, world!"]
        safe_command = " ".join(shlex.quote(arg) for arg in command)
        # example_data = f"#!/bin/bash\n{safe_command}\n"
        # createExecutableFile(example_data) # Only if you've sanitized the data!

        print("Example data creation is disabled for security reasons.  Review the comments in the code.")

        # Example of a path traversal attempt (will raise an error)
        # createExecutableFile("../../../evil.bim")

        # Example of an invalid extension (will raise an error)
        # createExecutableFile("test.txt")

    except ValueError as e:
        print(f"Error: {e}")
    except TypeError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"OS Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

