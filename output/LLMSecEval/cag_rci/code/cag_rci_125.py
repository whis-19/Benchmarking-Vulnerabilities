# Example (using parameterized queries with sqlite3):
    import sqlite3

    conn = sqlite3.connect('mydatabase.db')
    cursor = conn.cursor()

    username = form.username.data
    password = form.password.data  # Assuming already hashed

    # BAD (Vulnerable to SQL Injection):
    # query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

    # GOOD (Parameterized Query):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))

