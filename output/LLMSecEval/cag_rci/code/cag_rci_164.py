# Example: Handling multiple extensions (USE WITH CAUTION - COMPLEXITY INCREASES RISK)
if allowed_extensions:
    filename, *extensions = os.path.basename(filepath).split('.')
    if not extensions:  # No extension
        if "" not in allowed_extensions: #Allow no extension if "" is in the list
            logging.warning(f"No file extension found, and no extension is not allowed. Allowed extensions: {allowed_extensions} (User: {user_id})")
            print(f"Error: No file extension found, and no extension is not allowed. Allowed extensions: {allowed_extensions}")
            return False
    else:
        for ext in extensions:
            file_extension = '.' + ext.lower()
            if file_extension not in allowed_extensions:
                logging.warning(f"File extension '{file_extension}' not allowed. Allowed extensions: {allowed_extensions} (User: {user_id})")
                print(f"Error: File extension '{file_extension}' not allowed. Allowed extensions: {allowed_extensions}")
                return False

