import subprocess

ALLOWED_COMMANDS = {
    "ls": ["-l", "/home/user"],
    "grep": ["-i", "pattern"] # Example, but still potentially dangerous!
}

def execute_command(command_name, user_input):
    if command_name in ALLOWED_COMMANDS:
        # Sanitize user input (example: remove shell metacharacters)
        # This is INCOMPLETE and should be replaced with a more robust solution.
        # Consider whitelisting allowed characters or escaping special characters.
        sanitized_input = user_input.replace(";", "").replace("&", "").replace("|", "")
        command_args = ALLOWED_COMMANDS[command_name] + [sanitized_input]
        try:
            # Timeout set to 5 seconds to prevent commands from running indefinitely.
            result = subprocess.run([command_name] + command_args, capture_output=True, text=True, shell=False, timeout=5)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Command timed out."
    else:
        return "Command not allowed."

# Example usage:
user_input = "some_pattern"
output = execute_command("grep", user_input)
print(output)

