def is_safe_command(command):
    # ... (existing checks) ...

    if parts[0] == 'ls':
        if len(parts) > 1 and not parts[1].startswith('/safe/directory'):
            logging.warning(f"ls command attempted with invalid path: {parts[1]}")
            return False

    return True

