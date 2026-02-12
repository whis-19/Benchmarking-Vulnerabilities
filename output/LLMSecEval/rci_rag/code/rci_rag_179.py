import sys
import os
import re
import subprocess
import shlex
import glob
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def main():
    """
    This script takes a single command-line argument, prints it, trims trailing whitespace, and prints it again.
    It includes security measures to prevent command injection and other vulnerabilities.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.")
        print("Usage: python script.py <argument>")
        logging.error("Incorrect number of arguments provided.")
        sys.exit(1)

    input_arg = sys.argv[1]

    # Input Validation:  Strict allowlist of characters.  This is crucial for preventing command injection.
    # Only allow alphanumeric characters, underscores, hyphens, and periods.  Adjust as needed for your specific use case.
    # Example: If the argument is expected to be a filename with a `.txt` extension, the regex could be `^[a-zA-Z0-9_\-]+\.txt$`.
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", input_arg):
        print("Error: Invalid input.  Argument must contain only alphanumeric characters, underscores, hyphens, and periods.")
        logging.error(f"Invalid input received: {input_arg}")
        sys.exit(1)

    print("Original argument:", input_arg)
    logging.info(f"Original argument: {input_arg}")

    # Trim trailing whitespace
    trimmed_arg = input_arg.rstrip()

    print("Argument after trimming whitespace:", trimmed_arg)
    logging.info(f"Argument after trimming whitespace: {trimmed_arg}")

    # Example of constructing a command (AVOID if possible, use safer alternatives like subprocess.run with lists)
    # This is included to demonstrate the necessary escaping, but it's better to avoid string-based command construction.
    # Instead of constructing a string, use a list of arguments for subprocess.run.
    # shlex.quote is only needed when constructing a *single string* to be passed to subprocess.run with shell=True. It's not needed when passing a list of arguments.
    # command = f"echo {shlex.quote(trimmed_arg)}" # shlex.quote is essential for escaping.  DO NOT OMIT.
    # print("Executing command:", command)
    # try:
    #     result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True) # shell=True is generally discouraged, but if you must use it, ensure proper escaping.
    #     print("Command output:", result.stdout)
    #     print("Command error:", result.stderr)
    # except subprocess.CalledProcessError as e:
    #     print(f"Error executing command: {e}")
    #     sys.exit(1)

    # Safer alternative using subprocess.run with a list of arguments:
    command = ["echo", trimmed_arg] # No need for shlex.quote when using a list.
    print("Executing command:", command)
    logging.info(f"Executing command: {command}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Command output:", result.stdout)
        print("Command error:", result.stderr)
        logging.info(f"Command output: {result.stdout}")
        if result.stderr:
            logging.warning(f"Command error: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        logging.exception(f"Error executing command: {e}")
        sys.exit(1)

    # Example of using globbing as an alternative to shell=True for wildcard expansion
    # files = glob.glob("*.txt")
    # print("Found files:", files)

    # Example of using piping as an alternative to shell=True for piping
    # try:
    #     process1 = subprocess.run(["ls", "-l"], capture_output=True, text=True, check=True)
    #     process2 = subprocess.run(["grep", "txt"], input=process1.stdout, capture_output=True, text=True, check=True)
    #     print("Piped output:", process2.stdout)
    # except subprocess.CalledProcessError as e:
    #     print(f"Error executing command: {e}")
    #     sys.exit(1)

    # Example of reading data from a file with explicit encoding
    filename = "input.txt"
    max_file_size = 1024  # Maximum file size in bytes (1KB)

    try:
        file_size = os.path.getsize(filename)
        if file_size > max_file_size:
            print(f"Error: File size exceeds the maximum allowed size of {max_file_size} bytes.")
            logging.error(f"File size exceeds maximum allowed size: {file_size} bytes")
            sys.exit(1)

        with open(filename, "r", encoding="utf-8") as f:
            file_content = f.read()
            print("File content:", file_content)
            logging.info(f"File content read from {filename}: {file_content[:100]}...") # Log only the first 100 characters to avoid excessive logging
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        logging.error(f"File not found: {filename}")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"Error: Could not decode {filename} with utf-8 encoding.  Try a different encoding.")
        logging.error(f"Could not decode file {filename} with utf-8 encoding.")
        sys.exit(1)
    except OSError as e:
        print(f"Error: Could not access {filename}: {e}")
        logging.error(f"Could not access file {filename}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()

