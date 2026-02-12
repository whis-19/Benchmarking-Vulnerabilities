def validate_arguments(command_list):
    """Validates arguments based on the command."""
    command = command_list[0]
    args = command_list[1:]

    if command == 'ls':
        # Example: Allow only -l, -a, and -la as arguments for ls
        allowed_args = ['-l', '-a', '-la']
        for arg in args:
            if arg not in allowed_args:
                return False, f"Invalid argument for ls: {arg}"
    elif command == 'echo':
        # Example: Allow any string as an argument for echo (but still sanitize)
        for arg in args:
            if not re.match(r'^[a-zA-Z0-9_\-\s\.,]+$', arg): # More permissive, but still restricts
                return False, f"Invalid argument for echo: {arg}"
    # Add validation for other allowed commands as needed
    return True, None

