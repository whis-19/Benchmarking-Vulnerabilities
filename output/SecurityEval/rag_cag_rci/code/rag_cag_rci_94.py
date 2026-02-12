import mimetypes

    # ... inside the upload route ...
    content_type = file.content_type
    if content_type != 'application/xml':  # Or 'text/xml' depending on your needs
        os.remove(filepath)
        return jsonify({'message': 'Invalid content type.  Expected application/xml'}), 400

