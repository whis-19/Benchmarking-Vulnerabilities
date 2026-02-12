from pathlib import Path

    def is_safe_path(basedir, path, filename):
        """
        Safely checks if a path is within the allowed base directory using pathlib.
        Prevents path traversal attacks.
        """
        base_path = Path(basedir).resolve()
        file_path = (base_path / path / filename).resolve()
        return base_path in file_path.parents

