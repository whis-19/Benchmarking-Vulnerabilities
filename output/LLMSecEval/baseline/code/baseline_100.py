import bcrypt
import sqlite3

def create_user_bcrypt(username, password, db_path="users.db"):
    """Creates a new user in the database with a bcrypt hashed password."""

    # 1. Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # 2. Connect to the database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 3. Create the users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """)

        # 4. Insert the username and hashed password into the database
        try:
            cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                           (username, hashed_password.decode('utf-8')))  # Store as string
            conn.commit()
            print(f"User '{username}' created successfully (bcrypt).")
        except sqlite3.IntegrityError:
            print(f"Username '{username}' already exists.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")

    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")
    create_user_bcrypt(username, password)

