# Example of whitelisting allowed commands (very basic)
    allowed_commands = ["echo", "ls", "pwd"]  # Be extremely careful with what you allow!
    if echo_path not in allowed_commands:
        print(f"Error: Command '{echo_path}' is not allowed.")
        echo_path = None # Prevent execution

