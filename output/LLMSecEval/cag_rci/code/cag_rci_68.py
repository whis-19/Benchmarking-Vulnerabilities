# Example using python-magic for MIME type detection
import magic
import logging

logging.basicConfig(level=logging.ERROR)  # Configure logging

@app.route('/img')
def img():
    # ... (Authentication/Authorization) ...

    filepath = safe_join(IMAGE_BASE_DIR, filename)

    try:
        if not os.path.exists(filepath):
            return "File not found", 404

        if not os.access(filepath, os.R_OK):
            return "Insufficient permissions to read file", 403

        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return "File too large", 413

        try:
            mime = magic.Magic(mime=True)
            mimetype = mime.from_file(filepath)

            # Validate MIME type against allowed types
            if mimetype not in ['image/png', 'image/jpeg', 'image/gif']:  # Example
                return "Invalid file type", 400

        except Exception as e:
            logging.exception("Error detecting MIME type using python-magic.")
            # If python-magic fails, consider other content-based MIME type detection libraries
            # as a last resort.  If you MUST use mimetypes.guess_type, be extremely cautious.
            # mimetype = mimetypes.guess_type(filepath)[0] # Extension-based - VERY UNSAFE
            return "Internal Server Error", 500 # Or handle the error more gracefully

        response = make_response(send_file(filepath, mimetype=mimetype))
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" # Example CSP
        return response

    except Exception as e:
        logging.exception("Error serving file.")  # Log the error
        return "Internal Server Error", 500  # Return a generic message to the user

