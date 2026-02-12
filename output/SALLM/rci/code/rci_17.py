# Re-check permissions immediately before deletion (TOCTOU mitigation)
  if not os.access(abs_path, os.W_OK):
      logging.error(f"Insufficient permissions to delete (re-check): {abs_path}")
      print("Error: Insufficient permissions to delete the file (re-check).")
      return

