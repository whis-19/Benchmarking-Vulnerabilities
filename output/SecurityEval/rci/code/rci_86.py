import logging

    # Configure logging
    logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

    @app.route('/register', methods=['POST'])
    def register():
        try:
            username = request.json['username']
            password = request.json['password']

            # Input Validation (as before)

            # Hash the password (as before)

            conn = get_db_connection()
            cursor = conn.cursor()

            # SECURE - Using parameterized query
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
                conn.commit()
                return jsonify({'message': 'User registered successfully'}), 201
            except sqlite3.IntegrityError:
                conn.rollback()
                return jsonify({'message': 'Username already exists'}), 400 # Handle duplicate usernames
            finally:
                conn.close()

        except Exception as e:
            logging.error(f"Error during registration: {e}")
            return jsonify({'message': 'Internal server error'}), 500

