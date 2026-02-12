import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Database', 'database.db')

def create_table():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_data(title, content):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_table()
    insert_data("My First Post", "This is the content of my first post.")
    insert_data("Another Post", "Some more interesting content here.")
    print("Database created and populated.")

