import subprocess
import shlex
import re
import logging
import os
import json

# Load configuration (with validation)
try:
    with open("config.json", "r") as f:
        config = json.load(f)

        # Validate config structure
        if not isinstance(config.get("allowed_commands", []), list):
            raise ValueError("allowed_commands must be a list")
        if not isinstance(config.get("allowed_arguments", {}), dict):
            raise ValueError("allowed_arguments must be a dict")
        for cmd, args in config.get("allowed_arguments", {}).items():
            if not isinstance(cmd, str):
                raise ValueError("allowed_arguments keys must be strings (commands)")
            if not isinstance(args, list):
                raise ValueError(f"allowed_arguments[{cmd}] must be a list")
            for arg in args:
                if not isinstance(arg, str):
                    raise ValueError(f"allowed_arguments[{cmd}] elements must be strings")


except FileNotFoundError:
    config = {}

ALLOWED_COMMANDS = config.get("allowed_commands", ["ls", "pwd", "date"])
ALLOWED_ARGUMENTS = config.get("allowed_arguments", {
    "ls": ["-l", "/tmp", "/home"],
    "pwd": [],
    "date": ["+%Y-%m-%d", "+%H:%M:%S"]
})
STRICT_ARGUMENT_WHITELISTING = config.get("strict_argument_whitelisting", True)
LOG_LEVEL = config.get("log_level", "INFO")  # Default to INFO for better auditing
ALLOWED_BASE_DIRS = config.get("allowed_base_dirs", ["/tmp", "/home"]) # Add allowed base dirs to config

logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO))


def sanitize_ls_argument(arg, allowed_base_dirs=None):
    """Sanitizes ls arguments, ensuring they are within allowed base directories."""
    if allowed_base_dirs is None:
        allowed_base_dirs = ALLOWED_BASE_DIRS  # Use config value

    abs_path = os.path.abspath(arg)
    real_path = os.path.realpath(abs_path)  # Resolve symlinks

    is_allowed = False
    for base_dir in allowed_base_dirs:
        abs_base_dir = os.path.abspath(base_dir)
        if os.path.commonpath([abs_base_dir, real_path]) == abs_base_dir:
            is_allowed = True
            break

    if not is_allowed:
        raise ValueError(f"Path '{arg}' is outside the allowed base directories.")

    return real_path  # Return the real path


def default_sanitize_argument(arg):
    """Default sanitization: strip whitespace and quote."""
    return shlex.quote(arg.strip())


def execute_command(command, arguments=None):
    """
    Executes a command using subprocess, with security measures.
    """

    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Attempted execution of disallowed command: {command}")
        return -1, "Error: Command not allowed"

    try:
        cmd = [command]
        if arguments:
            if command in ALLOWED_ARGUMENTS:
                for arg in arguments:
                    # Normalize argument before checking
                    normalized_arg = arg.strip().lower()
                    if normalized_arg not in [a.strip().lower() for a in ALLOWED_ARGUMENTS[command]]:
                        logging.warning(f"Attempted execution of command '{command}' with disallowed argument: {arg}")
                        return -1, "Error: Argument not allowed"
            else:
                logging.warning(f"No argument whitelist defined for command '{command}'.")
                if STRICT_ARGUMENT_WHITELISTING:
                    logging.error(f"Strict argument whitelisting enabled.  Rejecting command '{command}'.")
                    return -1, "Error: No argument whitelist defined and strict whitelisting is enabled."
                else:
                    logging.warning("Proceeding with caution.")

            sanitized_arguments = []
            for arg in arguments:
                if command == "ls":
                    try:
                        sanitized_arg = sanitize_ls_argument(arg)
                    except ValueError as e:
                        logging.error(f"Invalid argument for ls: {e}")
                        return -1, str(e)  # Return the specific error message
                else:
                    sanitized_arg = default_sanitize_argument(arg)  # Use default sanitization
                sanitized_arguments.append(sanitized_arg)

            cmd.extend(sanitized_arguments)

        # No longer needed if sanitize_ls_argument handles path restrictions
        # Resolve absolute paths (example - adapt as needed)
        #if command == "ls":
        #    cmd = [os.path.abspath(c) if c.startswith("/") else c for c in cmd]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logging.error(f"Command failed with return code {result.returncode}: {result.stderr}")

        return result.returncode, result.stdout + result.stderr

    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        return -1, "Error: Command not found"
    except Exception as e:
        logging.exception(f"Error executing command: {e}")
        return -1, "Error: An error occurred"

