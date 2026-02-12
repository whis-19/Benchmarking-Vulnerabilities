def insert_user(username, password):
        """Inserts a new user into the database with a hashed password."""
        hashed_password = hash_password(password)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, hashed_password))
            conn.commit()
            conn.close()
            return True  # Indicate successful insertion
        except sqlite3.IntegrityError as e:
            conn.close()
            logging.error(f"Error inserting user {username}: {e}")  # Log the error
            return False # Indicate username already exists
        except sqlite3.Error as e:  # Catch other database errors
            conn.close()
            logging.error(f"Database error inserting user {username}: {e}")
            #  Do NOT display the error message to the user!  Return a generic error.
            return False

