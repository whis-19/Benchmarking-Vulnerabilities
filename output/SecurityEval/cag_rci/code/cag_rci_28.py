def is_allowed_file_type(filename, filepath):
    """Checks if the file type is allowed based on its content."""
    mime = magic.Magic(mime=True)
    try:
        with open(filepath, "rb") as f:
            file_content = f.read(2048)  # Read the first 2KB
    except Exception as e:
        logging.error(f"Error reading file for MIME type check: {e}")
        return False
    mime_type = mime.from_buffer(file_content)

    allowed_mime_types = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".txt": "text/plain",
        ".pdf": "application/pdf",
    }

    ext = "." + filename.rsplit(".", 1)[1].lower()

    if ext in allowed_mime_types:
        return mime_type == allowed_mime_types[ext]
    else:
        return False

# ...

        for filename in os.listdir(user_dir):  # Use user_dir directly
            filepath = os.path.join(user_dir, filename) # Construct the full path
            if os.path.isfile(filepath) and is_allowed_file_extension(filename):
                # Read the file content for MIME type checking
                if is_allowed_file_type(filename, filepath):
                    files.append(filename)  # Or filepath if you need the full path

