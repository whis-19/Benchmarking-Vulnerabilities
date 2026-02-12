import magic

def validate_file_content(filepath, expected_mime_type):
    """
    Validates the content of a file based on its MIME type.

    Args:
        filepath (str): The path to the file.
        expected_mime_type (str): The expected MIME type of the file.

    Returns:
        bool: True if the file content matches the expected MIME type, False otherwise.
    """
    try:
        mime = magic.Magic(mime=True).from_file(filepath)
        return mime == expected_mime_type
    except Exception as e:
        print(f"Error validating file content: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = str(uuid.uuid4()) + '.' + file_extension
            filename = secure_filename(unique_filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                file.save(filepath)
            except Exception as e:
                print(f"Error saving file: {e}")
                return "Error saving file."

            # Content validation
            if file_extension in ['jpg', 'jpeg', 'png', 'gif']:
                expected_mime = 'image/' + file_extension  # Adjust for specific image types
                if not validate_file_content(filepath, expected_mime):
                    os.remove(filepath)  # Remove the invalid file
                    return "Invalid image file content."
            elif file_extension == 'pdf':
                if not validate_file_content(filepath, 'application/pdf'):
                    os.remove(filepath)
                    return "Invalid PDF file content."
            # Add more content validation for other allowed file types

            return f'File uploaded successfully. Saved as: {filename}'
        else:
            return 'Invalid file type or file not allowed.'

    return '''... (HTML form) ...'''

