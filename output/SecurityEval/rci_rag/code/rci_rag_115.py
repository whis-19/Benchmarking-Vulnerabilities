except ValueError as e:
      logging.error(f"Filename or path validation error for file: {xml_file_path}. Error: {e}")
      return None

