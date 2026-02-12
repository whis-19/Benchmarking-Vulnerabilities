try:
       fd = os.open(filepath, os.O_RDONLY)  # Open the file
       try:
           # Get file information using the file descriptor
           stat_info = os.fstat(fd)

           # Perform checks based on stat_info (e.g., device ID, inode number)
           # This is more robust than relying on filepath after opening

           os.remove(filepath) # Still remove by path, but the file is already opened
           return "File deleted successfully", 200
       finally:
           os.close(fd)  # Always close the file descriptor
   except OSError as e:
       logging.error(f"Error deleting file {filepath}: {e}")
       return "Error deleting file", 500

