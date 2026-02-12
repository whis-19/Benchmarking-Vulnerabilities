@app.route('/download/<filename>')
def download_file(filename):
    """Downloads a file from the uploads folder."""
    # Robust filename sanitization to prevent path traversal and length issues
    if not re.match("^(?!\.)[a-zA-Z0-9._-]{1,255}$", filename):
        logging.warning(f"Invalid filename: {filename}")
        return jsonify({"error": "Invalid filename"}), 400

    db = connect_to_db()
    if db:
        try:
            cursor = db.cursor()
            # Use parameterized query to prevent SQL injection
            sql = "SELECT filepath, original_filename FROM files WHERE filepath LIKE %s" # Assuming you store original_filename
            val = (f"%{filename}",)  # Use LIKE to find the filename within the path
            cursor.execute(sql, val)
            result = cursor.fetchone()

            if result:
                filepath, original_filename = result
                # Validate the *entire* filepath retrieved from the database
                if not os.path.abspath(filepath).startswith(os.path.abspath(app.config["UPLOAD_FOLDER"])):
                    logging.error(f"Path traversal attempt: {filepath}")
                    return jsonify({"error": "Invalid filepath"}), 500

                # Validate the original filename (if you store it)
                if not re.match("^(?!\.)[a-zA-Z0-9._-]{1,255}$", original_filename):
                    logging.error(f"Invalid original filename: {original_filename}")
                    return jsonify({"error": "Invalid original filename"}), 500

                logging.info(f"Downloading file: {original_filename}")
                return send_from_directory(app.config["UPLOAD_FOLDER"], os.path.basename(filepath), as_attachment=True, mimetype='application/pdf')  # Added mimetype
            else:
                logging.warning(f"File not found in database: {filename}")
                return jsonify({"error": "File not found"}), 404
        except MySQLError as err:
            logging.error(f"Error retrieving filepath from database: {err}")
            return jsonify({"error": "Database error"}), 500
        finally:
            if db.is_connected():
                cursor.close()
                db.close()
    else:
        return jsonify({"error": "Database connection failed"}), 500

