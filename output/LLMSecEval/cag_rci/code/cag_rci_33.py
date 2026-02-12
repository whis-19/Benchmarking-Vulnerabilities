# 1. Input Validation and Sanitization (Stronger)
# Sanitize filename (remove any directory components) - BEFORE regex check
filename = os.path.basename(filename)

# Whitelist allowed characters (alphanumeric, underscore, period)
# The regex allows alphanumeric characters, underscores, and periods.
# Other characters, such as spaces or special characters, are disallowed to prevent
# unexpected behavior or potential exploits.
if not re.match(r"^[a-zA-Z0-9_.]+\.txt$", filename):
    print("Error: Invalid filename. Only alphanumeric, underscores, and periods allowed in .txt files.")
    return

# Examples of blocked filenames:
# "file with spaces.txt" (blocked because of spaces)
# "file!with@symbols.txt" (blocked because of special characters)
# "file.txt.exe" (blocked because it doesn't end with .txt after the allowed characters)
# ".hidden_file.txt" (blocked because it starts with a period, which might be undesirable)

# 2. Path Traversal Prevention (Using os.path.normpath)
allowed_directory = "/tmp"  # Change this to your desired directory
filepath = os.path.join(allowed_directory, filename)
filepath = os.path.normpath(filepath)  # Removes redundant separators and resolves relative paths like '..'
# The startswith check is crucial to ensure that the final filepath remains within the allowed_directory.
# If it doesn't, it indicates a path traversal attempt.
if not filepath.startswith(allowed_directory):
    print("Error: Invalid filename. Path traversal detected.")
    return

# ... (rest of write_output_to_file)

def process_log_file_safe(log_file):
    try:
        with open(log_file, 'r') as f:
            for line in f:
                if "error" in line.lower():  # Case-insensitive search
                    print(line.strip()) # Print the line without leading/trailing whitespace
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file}")
    except IOError as e:
        print(f"Error reading log file: {e}")

# ... (rest of the code)

# Example of how an unsanitized filename could lead to command execution elsewhere
def process_log_file(log_file):
    # Vulnerable: If log_file is attacker-controlled, this is command injection
    # NEVER use shell=True with user-provided input. Even if shell=False is the default,
    # future modifications could inadvertently introduce this vulnerability.
    try:
        subprocess.run(["grep", "error", log_file], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error processing log file: {e}")

# ... (rest of the code)

# Authentication Example (Weak - DO NOT USE IN PRODUCTION)
# def authenticate_user(username, password):
#     # Storing passwords in plain text is extremely insecure!
#     users = {"admin": "password123"}
#     if username in users and users[username] == password:
#         return True
#     else:
#         return False

# Static Analysis Tools (Examples)
# Bandit: A security linter for Python.
# Pylint: A code analysis tool with security plugins.

