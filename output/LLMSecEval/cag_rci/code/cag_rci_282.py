try:
        filepath = os.path.realpath(filepath)
    except OSError:
        return None, "File does not exist or is inaccessible."

