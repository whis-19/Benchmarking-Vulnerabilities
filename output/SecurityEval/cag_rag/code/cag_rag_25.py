import magic

def validate_content_type(filepath, expected_mime_types):
    """Validates the file's content type against a list of expected MIME types."""
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_file(filepath)
        return file_mime_type in expected_mime_types
    except Exception as e:
        print(f"Error validating content type: {e}")
        return False

# Example usage in the upload function:
# After saving the file:
expected_mime_types = {
    'image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'
}  # Adjust based on ALLOWED_EXTENSIONS
if not validate_content_type(unique_filename, expected_mime_types):
    os.remove(unique_filename)  # Remove the invalid file
    return "Invalid file content", 400

