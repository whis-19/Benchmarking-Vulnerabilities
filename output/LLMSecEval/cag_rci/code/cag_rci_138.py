import shlex

    user_input = argv[2]  # Get user input from the command line
    escaped_input = shlex.quote(user_input)
    command = ["echo", f"Hello, {escaped_input}!"]  # Still safer to avoid this entirely
    result = subprocess.run(command, capture_output=True, text=True, check=True)

