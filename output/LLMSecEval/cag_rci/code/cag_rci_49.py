import os

    UPLOAD_FOLDER = "/path/to/your/upload/directory"  # Replace with your actual path

    def validate_file_path(filepath: str) -> str:
        """Validates that the filepath is within the allowed upload directory."""
        abs_upload_folder = os.path.abspath(UPLOAD_FOLDER)
        abs_filepath = os.path.abspath(filepath)

        # Use os.path.commonpath to find the common path between the two paths
        common_path = os.path.commonpath([abs_upload_folder, abs_filepath])

        if common_path != abs_upload_folder:
            raise ValueError("Invalid file path: Attempt to access outside upload directory.")

        return abs_filepath

