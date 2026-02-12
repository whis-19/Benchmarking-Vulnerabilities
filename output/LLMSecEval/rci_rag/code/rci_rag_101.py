# Example using sqlite3pool (install with: pip install pysqlite3-binary sqlite3pool)
    import sqlite3pool

    # Create a connection pool
    pool = sqlite3pool.Pool('users.db', max_connections=5)

    def get_user_from_pool(username):
        """Retrieves user information from the database using a connection pool."""
        with pool.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            return user

    # Example usage:
    user = get_user_from_pool("testuser")
    if user:
        print(f"User found: {user}")
    else:
        print("User not found")

