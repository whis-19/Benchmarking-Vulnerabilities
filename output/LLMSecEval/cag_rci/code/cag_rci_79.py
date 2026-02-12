@app.route('/uploads/<filename>')
    @login_required
    def download_file(filename):
        user_id = session['user_id']

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id FROM files WHERE filepath = %s AND user_id = %s", (os.path.join(app.config['UPLOAD_FOLDER'], filename), user_id)) # Check if the user owns the file
                file_record = cursor.fetchone()

                if file_record:
                    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
                else:
                    abort(403)  # Forbidden - User doesn't have permission
            except mysql.connector.Error as err:
                logging.error("File download authorization error.")
                logging.debug(f"Detailed file download authorization error: {err}")
                abort(500)
            finally:
                cursor.close()

