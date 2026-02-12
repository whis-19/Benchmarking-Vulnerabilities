@image_route('/images')
    def serve_image(filename):
        # ... (rest of the function) ...

        if os.path.isfile(filepath):
            try:
                return send_from_directory(IMAGES_FOLDER, sanitized_filename)
            except FileNotFoundError:
                logging.warning(f"File not found: {filepath}")
                abort(404, "Image not found")
            except Exception as e:
                logging.exception(f"Error serving file: {e}")  # Log the full exception
                abort(500, "Internal Server Error") # Internal Server Error
        else:
            abort(404, "Image not found")  # Not Found

