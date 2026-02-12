import sqlite3

    def get_user_by_username(username):
        try:
            with sqlite3.connect('your_database.db') as conn: # Consider using an environment variable for the database path
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                return user
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

    # Note: 'your_database.db' should NOT be committed to version control.
    # Consider using an environment variable to configure the database path.

