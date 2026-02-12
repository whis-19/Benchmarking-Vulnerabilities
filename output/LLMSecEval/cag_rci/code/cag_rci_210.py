import os

    DATABASE = os.environ.get('DATABASE_URL', 'default_database.db') # Default value if not set

    def get_db_connection():
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn

