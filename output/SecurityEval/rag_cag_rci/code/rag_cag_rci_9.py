from flask import jsonify

    if not filename:
        logger.warning("getFileData: Filename is missing in the request.")
        return jsonify({"error": "Filename is required"}), 400

