# (In a separate route, e.g., /images/<filename>)
    @app.route('/images/<filename>')
    def get_image(filename):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.isfile(filepath):
            abort(404)

        # Determine the content type based on the *actual* file type
        mime = magic.Magic(mime=True)
        content_type = mime.from_file(filepath)

        # Force download and set the filename
        return send_file(filepath, mimetype=content_type, as_attachment=True, download_name=filename)

