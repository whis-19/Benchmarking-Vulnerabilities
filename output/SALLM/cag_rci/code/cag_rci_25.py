import os

    def is_safe_path(filepath, basepath):
        """Checks if the filepath is within the allowed basepath to prevent path traversal."""
        try:
            filepath = os.path.abspath(filepath)
            basepath = os.path.abspath(basepath)
            common = os.path.commonpath([basepath, filepath])
            return common == basepath
        except ValueError:
            # Handle cases where paths are on different drives (Windows)
            return False
        except OSError as e:
            logging.error(f"Error resolving path: {e}")
            return False

