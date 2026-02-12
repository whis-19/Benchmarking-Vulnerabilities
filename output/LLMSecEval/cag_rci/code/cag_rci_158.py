import os

            ALLOWED_DIRECTORIES = ["/path/to/safe/directory", "/another/safe/directory"]

            def is_path_safe(path, allowed_directories):
                """
                Checks if the path is within one of the allowed directories.
                """
                normalized_path = os.path.normpath(path)
                for allowed_dir in allowed_directories:
                    normalized_allowed_dir = os.path.normpath(allowed_dir)
                    if normalized_path.startswith(normalized_allowed_dir):
                        return True
                return False

