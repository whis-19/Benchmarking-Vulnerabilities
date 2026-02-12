# Vulnerable code (example)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    query = f"INSERT INTO files (path) VALUES ('{file_path}')"  # Vulnerable!
    cursor.execute(query)

