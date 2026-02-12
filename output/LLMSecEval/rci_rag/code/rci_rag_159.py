try:
      # Check file size (example: limit to 1MB)
      file_size = os.path.getsize(filepath)
      if file_size > 1024 * 1024:
          logging.error(f"File '{filename}' exceeds maximum allowed size.")
          return None

      with open(filepath, "r") as f:
          content = f.read()
          return content

