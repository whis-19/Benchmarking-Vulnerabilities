import subprocess

def execute_command_safely(command, args):
    """
    Executes a command using subprocess, taking precautions against command injection.
    """
    try:
        # Use a list for the command and arguments to avoid shell injection
        process = subprocess.run([command] + args, capture_output=True, text=True, check=True, shell=False)
        return process.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
        return None

# Example usage (replace with your actual command and arguments)
# IMPORTANT:  Only use commands that are statically defined and vetted.
# NEVER allow user input to directly influence the command or arguments.
# command = "/usr/bin/ls"  # Example:  A safe, statically defined command
# args = ["-l", "/tmp"]  # Example: Safe, statically defined arguments

# output = execute_command_safely(command, args)

# if output:
#     print(output)

