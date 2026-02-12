try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(filepath)
        # Double check against file extension
        ext = filename.rsplit('.', 1)[1].lower()
        if ext in ['jpg', 'jpeg']:
            expected_mime = 'image/jpeg'
        elif ext == 'png':
            expected_mime = 'image/png'
        elif ext == 'gif':
            expected_mime = 'image/gif'
        elif ext == 'pdf':
            expected_mime = 'application/pdf'
        elif ext == 'txt':
            expected_mime = 'text/plain'
        else:
            expected_mime = None

        if expected_mime and mime_type != expected_mime:
            print(f"MIME type mismatch: Expected {expected_mime}, got {mime_type}")
            mime_type = 'application/octet-stream' # Default to binary
    except Exception as e:
        print(f"Error determining MIME type: {e}")
        mime_type = 'application/octet-stream'  # Default to binary

