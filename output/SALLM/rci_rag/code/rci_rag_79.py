import shlex
import subprocess

def execute_command_with_quoted_args(command, args, working_directory, timeout):
    """
    Executes a command with arguments, using shlex.quote() for sanitization.
    THIS IS STILL RISKY AND SHOULD BE AVOIDED IF POSSIBLE.
    PREFER A COMPLETE ALLOWLIST.
    """
    try:
        # Sanitize each argument using shlex.quote()
        quoted_args = [shlex.quote(arg) for arg in args]

        # Construct the full command list
        full_command = [command] + quoted_args

        process = subprocess.Popen(
            full_command,
            cwd=working_directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            executable="/bin/bash" # Explicitly set the executable
        )

        stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode != 0:
            raise Exception(f"Command failed with error: {stderr.decode()}")

        return stdout.decode()

    except subprocess.TimeoutExpired:
        process.kill()
        raise Exception("Command timed out")
    except Exception as e:
        raise Exception(f"Error executing command: {e}")


# Example Usage (WITH EXTREME CAUTION!)
# THIS IS FOR ILLUSTRATIVE PURPOSES ONLY.  DO NOT USE THIS IN PRODUCTION
# WITHOUT CAREFUL CONSIDERATION AND TESTING.
#
#  A much safer approach is to include the entire command, including arguments,
#  in the allowlist.

#  Example:
#  safe_command = "ls"
#  safe_args = ["-l", "/tmp"]
#  result = execute_command_with_quoted_args(safe_command, safe_args, "/tmp", 5)
#  print(result)

#  DANGEROUS EXAMPLE (DO NOT USE IN PRODUCTION):
#  command = "ls"
#  args = ["-l", "; rm -rf /"]  # THIS IS A TERRIBLE IDEA!
#  # Even with shlex.quote(), this is still risky because the command itself is not validated.
#  # result = execute_command_with_quoted_args(command, args, "/tmp", 5) # DO NOT DO THIS!
#  # print(result)

