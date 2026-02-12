import bcrypt

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def insert_user(username, password_hash): # No salt needed with bcrypt
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, password_hash))
        conn.commit()
        print(f"User '{username}' successfully registered.")
    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists. Please choose a different username.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

# In register_user():
    password_hash = hash_password(password)
    insert_user(username, password_hash)

