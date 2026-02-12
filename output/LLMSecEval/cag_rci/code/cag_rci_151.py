import os
import re
import subprocess

ALLOWED_COMMANDS = {'head': ['-n']}
FULL_PATH_HEAD = "/usr/bin/head"

def execute_head_safely(filename, num_lines):
    """Safely executes head command using subprocess, with strong validation."""

    if not isinstance(num_lines, int) or num_lines <= 0:
        print("Error: Invalid number of lines.")
        return 1

    if not is_valid_filename(filename):
        print("Error: Invalid filename.")
        return 1

    try:
        # Build the command arguments directly, avoiding shell interpretation
        command = [FULL_PATH_HEAD, '-n', str(num_lines), filename]  # Convert num_lines to string

        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
        print(result.stderr)  # Consider sanitizing stderr before printing
        return 0

    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with return code {e.returncode}")
        print(e.stderr)  # Consider sanitizing stderr before printing
        return 1
    except FileNotFoundError:
        print("Error: Command not found.")
        return 1

def is_valid_filename(filename):
    """Validates filename to prevent path traversal and other issues."""
    pattern = r"^[a-zA-Z0-9._-]+$"
    if not re.match(pattern, filename):
        return False
    if os.path.isabs(filename) or ".." in filename:
        return False
    return True

def main():
    filename = input("Enter filename: ")
    num_lines = input("Enter number of lines: ")

    if not is_valid_filename(filename):
        print("Error: Invalid filename.")
        return

    try:
        num_lines = int(num_lines)
    except ValueError:
        print("Error: Invalid number of lines.")
        return

    execute_head_safely(filename, num_lines)

if __name__ == "__main__":
    main()

