from flask import send_file

    @app.route('/img/<filename>')
    def get_image(filename):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            return send_file(filepath, as_attachment=True)  # Force download
        except FileNotFoundError:
            return Response("Image not found.", status=404)

