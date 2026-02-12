@app.route('/upload_image', methods=['POST'])
    @login_required
    def upload_image():
        # ...
        try:
            image_file.save(filepath)
            user_id = session['user_id']
            db = get_db()
            cur = db.cursor()
            cur.execute("BEGIN TRANSACTION")  # Start transaction
            cur.execute("INSERT INTO images (filename, filepath, user_id) VALUES (?, ?, ?)", (unique_filename, filepath, user_id))
            db.commit()  # Commit transaction
            return jsonify({'message': 'Image uploaded successfully', 'filename': unique_filename}), 200

        except Exception as e:
            db.rollback()  # Rollback transaction
            print(f"Error during image upload: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'message': 'Image upload failed'}), 500

