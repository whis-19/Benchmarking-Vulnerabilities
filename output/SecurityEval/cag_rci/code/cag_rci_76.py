from flask import make_response

    @app.route('/uploads/<filename>')
    def serve_file(filename):
        response = make_response(send_from_directory(UPLOAD_FOLDER, filename))
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return response

