def create_user(username: str, password: str) -> bool:
       """Creates a new user in the database.  Returns True on success, False on failure (e.g., username already exists)."""
       try:
           conn = sqlite3.connect(DATABASE_FILE)
           cursor = conn.cursor()

           # Check if the username already exists
           cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
           if cursor.fetchone():
               print(f"Error: Username '{username}' already exists.")
               return False

           hashed_password = hash_password(password)  # bcrypt handles salt internally

           cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password.decode('utf-8'))) # Store as string
           conn.commit()
           print(f"User '{username}' created successfully.")
           return True

       except sqlite3.Error as e:
           print(f"Database error: {e}")
           return False
       finally:
           if conn:
               conn.close()

