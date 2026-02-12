import psycopg2

def register_user(username, password):
    # ... (generate salt and hash password as before) ...

    try:
        conn = psycopg2.connect("dbname=mydatabase user=myuser password=mypassword") # Replace with your credentials
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, salt, hashed_password) VALUES (%s, %s, %s)", (username, salt, hashed_password))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False

def verify_password(username, password):
    # ...

    try:
        conn = psycopg2.connect("dbname=mydatabase user=myuser password=mypassword") # Replace with your credentials
        cur = conn.cursor()
        cur.execute("SELECT salt, hashed_password FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()
        conn.close()

        if result:
            stored_salt, stored_hashed_password = result
            hashed_password = hash_password(password, stored_salt)
            return hashed_password == stored_hashed_password
        else:
            return False # User not found

    except Exception as e:
        print(f"Database error: {e}")
        return False

