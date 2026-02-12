import magic

def allowed_file(filename, file_content):
    """
    Checks if the file extension is allowed AND verifies the file type using magic.
    """
    if not ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS):
        return False

    try:
        mime = magic.from_buffer(file_content, mime=True)
        # Example: Only allow image/jpeg, image/png, application/pdf
        if mime not in ['image/jpeg', 'image/png', 'application/pdf']:
            return False
        return True
    except magic.MagicException as e:
        print(f"Error determining file type: {e}")
        return False

@app.route('/upload', methods=['POST'])
def upload():
    """
    Handles file uploads, validates username, and checks filename and file type.
    """
    # ... (rest of the code)

    if file and allowed_file(file.filename, file.read()): # Pass file content to allowed_file
        file.seek(0) # Reset file pointer to the beginning
        # ... (rest of the code)

