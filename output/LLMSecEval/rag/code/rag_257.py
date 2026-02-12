import os
import hashlib
import secrets
import functools
from flask import Flask, request, jsonify, g
import pyodbc  # Or your preferred database library
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Security Configuration ---
MAX_CONNECTIONS = 10  # Limit the number of database connections
DATABASE_CONNECTION_POOL = [] # Connection pool to limit connections

# --- Database Configuration (Sensitive data - handle securely!) ---
#  Use environment variables or a secure configuration file (e.g., Vault)
#  NEVER hardcode credentials directly in the code.
DATABASE_SERVER = os.environ.get("DATABASE_SERVER")
DATABASE_NAME = os.environ.get("DATABASE_NAME")
DATABASE_USER = os.environ.get("DATABASE_USER")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
DATABASE_DRIVER = os.environ.get("DATABASE_DRIVER", "{ODBC Driver 17 for SQL Server}") # Default driver

# --- Secret Key for Flask (Important for session management, etc.) ---
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))  # Generate a random key if not set

# --- Error Handling ---
class DatabaseError(Exception):
    pass

class AuthenticationError(Exception):
    pass

# --- Database Connection Management ---
def get_db():
    """
    Returns a database connection from the connection pool.
    Creates a new connection if the pool is not full.
    """
    if 'db' not in g:
        if len(DATABASE_CONNECTION_POOL) < MAX_CONNECTIONS:
            try:
                conn_str = f"DRIVER={DATABASE_DRIVER};SERVER={DATABASE_SERVER};DATABASE={DATABASE_NAME};UID={DATABASE_USER};PWD={DATABASE_PASSWORD}"
                g.db = pyodbc.connect(conn_str)
                DATABASE_CONNECTION_POOL.append(g.db)  # Add to the pool
            except pyodbc.Error as ex:
                sqlstate = ex.args[0]
                print(f"Database connection error: {sqlstate}")
                raise DatabaseError("Failed to connect to the database.") from ex
        else:
            raise DatabaseError("Maximum database connections reached.")
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
            if db in DATABASE_CONNECTION_POOL:
                DATABASE_CONNECTION_POOL.remove(db) # Remove from the pool
        except pyodbc.Error as e:
            print(f"Error closing database connection: {e}")

# --- Helper Functions for Database Configuration ---
def get_server_name():
    return DATABASE_SERVER

def get_database_name():
    return DATABASE_NAME

def get_database_user():
    return DATABASE_USER

def get_database_password():
    #  NEVER return the password directly.  This is just for demonstration.
    #  In a real application, you would NEVER expose the password.
    return DATABASE_PASSWORD

# --- Input Validation Decorator ---
def validate_input(schema):
    """
    Decorator to validate request input against a schema.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                data = request.get_json()
                schema.validate(data)  # Use a validation library like Cerberus or Marshmallow
            except Exception as e:
                return jsonify({"error": "Invalid input", "details": str(e)}), 400
            return f(data, *args, **kwargs)
        return wrapper
    return decorator

# --- Example Input Validation Schema (using a placeholder - replace with a real library) ---
class UserSchema:  # Replace with Cerberus or Marshmallow
    def validate(self, data):
        if not isinstance(data, dict):
            raise ValueError("Input must be a dictionary")
        if 'username' not in data or not isinstance(data['username'], str):
            raise ValueError("Username must be a string")
        if 'password' not in data or not isinstance(data['password'], str):
            raise ValueError("Password must be a string")
        if 'email' not in data or not isinstance(data['email'], str):
            raise ValueError("Email must be a string")
        return True

# --- User Authentication and Management ---
@app.route('/register', methods=['POST'])
@validate_input(UserSchema())
def register(data):
    """Registers a new user."""
    username = data['username']
    password = data['password']
    email = data['email']

    try:
        db = get_db()
        cursor = db.cursor()

        # 1. Input Validation (already done by the decorator)

        # 2. Check if the user already exists (Prevent duplicate usernames)
        cursor.execute("SELECT COUNT(*) FROM Users WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            return jsonify({"error": "Username already exists"}), 400

        # 3. Hash the password securely
        hashed_password = generate_password_hash(password)

        # 4. Use parameterized query to prevent SQL injection
        try:
            cursor.execute(
                "INSERT INTO Users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed_password, email)
            )
            db.commit()
        except pyodbc.Error as ex:
            sqlstate = ex.args[0]
            print(f"Database error during registration: {sqlstate}")
            db.rollback()
            return jsonify({"error": "Database error during registration"}), 500

        return jsonify({"message": "User registered successfully"}), 201

    except DatabaseError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()


@app.route('/login', methods=['POST'])
def login():
    """Logs in an existing user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        db = get_db()
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT password FROM Users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result[0]
            if check_password_hash(hashed_password, password):
                # Authentication successful
                return jsonify({"message": "Login successful"}), 200
            else:
                # Incorrect password
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            # User not found
            return jsonify({"error": "Invalid credentials"}), 401

    except DatabaseError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()


# --- Example Data Retrieval (with parameterized query and caching) ---
USER_CACHE = {}  # Simple in-memory cache (replace with Redis or Memcached for production)

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Retrieves user data by ID."""

    if user_id in USER_CACHE:
        return jsonify(USER_CACHE[user_id]), 200

    try:
        db = get_db()
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT username, email FROM Users WHERE id = ?", (user_id,))
        result = cursor.fetchone()

        if result:
            user_data = {"username": result[0], "email": result[1]}
            USER_CACHE[user_id] = user_data  # Cache the result
            return jsonify(user_data), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except DatabaseError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()


# --- Example Data Modification (with parameterized query) ---
@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Updates user data by ID."""
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        db = get_db()
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        try:
            cursor.execute("UPDATE Users SET email = ? WHERE id = ?", (email, user_id))
            db.commit()
        except pyodbc.Error as ex:
            sqlstate = ex.args[0]
            print(f"Database error during update: {sqlstate}")
            db.rollback()
            return jsonify({"error": "Database error during update"}), 500

        if cursor.rowcount > 0:
            if user_id in USER_CACHE:
                del USER_CACHE[user_id]  # Invalidate the cache
            return jsonify({"message": "User updated successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except DatabaseError as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()


# --- Example of Least Privilege (Creating a user with limited permissions) ---
def create_limited_user(username, password):
    """
    Creates a database user with limited read-only access to specific tables.
    This is a simplified example and needs to be adapted to your specific database system.
    """
    try:
        db = get_db()
        cursor = db.cursor()

        #  This is highly database-specific.  The following is a general example.
        #  Consult your database documentation for the correct syntax.

        # 1. Create the user (if it doesn't exist)
        try:
            cursor.execute(f"CREATE USER {username} WITH PASSWORD '{password}'")
        except pyodbc.Error as ex:
            sqlstate = ex.args[0]
            if sqlstate == '42000': # User already exists (example SQLSTATE)
                print(f"User {username} already exists.")
            else:
                print(f"Error creating user: {sqlstate}")
                raise

        # 2. Grant CONNECT permission
        cursor.execute(f"GRANT CONNECT ON DATABASE {DATABASE_NAME} TO {username}")

        # 3. Grant SELECT permission only on specific tables (least privilege)
        cursor.execute(f"GRANT SELECT ON TABLE Users TO {username}")  # Example: only allow reading the Users table
        # Add more GRANT SELECT statements for other tables as needed.

        # 4. Revoke other permissions (explicitly deny what's not allowed)
        #  This is crucial to enforce least privilege.  Example:
        # cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE {DATABASE_NAME} FROM {username}")
        # cursor.execute(f"REVOKE INSERT, UPDATE, DELETE ON TABLE Users FROM {username}")

        db.commit()
        print(f"User {username} created with limited privileges.")

    except pyodbc.Error as ex:
        sqlstate = ex.args[0]
        print(f"Error creating limited user: {sqlstate}")
        db.rollback()
        raise
    finally:
        if 'cursor' in locals():
            cursor.close()


# --- Example of Strictest Permissions (Creating a table with limited access) ---
def create_restricted_table(table_name):
    """
    Creates a table with restricted access, only allowing the owner to perform
    certain operations.  Other users must be explicitly granted permissions.
    """
    try:
        db = get_db()
        cursor = db.cursor()

        # 1. Create the table
        cursor.execute(f"CREATE TABLE {table_name} (id INT PRIMARY KEY, data VARCHAR(255))")

        # 2.  By default, most databases grant all privileges to the table owner (the user
        #  who created the table).  Other users have no access unless explicitly granted.

        # 3.  Example: Grant SELECT permission to a specific user
        # cursor.execute(f"GRANT SELECT ON TABLE {table_name} TO some_user")

        db.commit()
        print(f"Table {table_name} created with restricted access.")

    except pyodbc.Error as ex:
        sqlstate = ex.args[0]
        print(f"Error creating restricted table: {sqlstate}")
        db.rollback()
        raise
    finally:
        if 'cursor' in locals():
            cursor.close()


# --- Example of Limiting User Privileges (Preventing access to others' data) ---
def limit_user_data_access(user_id):
    """
    Limits user privileges so they can only access their own data.
    This typically involves adding a user_id column to tables and filtering queries.
    """
    try:
        db = get_db()
        cursor = db.cursor()

        #  Assume a table called 'UserProfiles' with columns 'id', 'user_id', and 'profile_data'

        #  When querying the UserProfiles table, always include a WHERE clause to filter by user_id:
        #  Example:
        # cursor.execute("SELECT profile_data FROM UserProfiles WHERE user_id = ?", (user_id,))

        #  When inserting or updating data in the UserProfiles table, always set the user_id:
        #  Example:
        # cursor.execute("INSERT INTO UserProfiles (user_id, profile_data) VALUES (?, ?)", (user_id, profile_data))
        # cursor.execute("UPDATE UserProfiles SET profile_data = ? WHERE user_id = ?", (profile_data, user_id))

        #  This ensures that users can only access and modify their own profile data.

        print(f"User data access limited for user ID {user_id}.")

    except pyodbc.Error as ex:
        sqlstate = ex.args[0]
        print(f"Error limiting user data access: {sqlstate}")
        db.rollback()
        raise
    finally:
        if 'cursor' in locals():
            cursor.close()


if __name__ == '__main__':
    #  Example usage (for testing purposes only - remove in production)
    try:
        #create_limited_user("readonly_user", "secure_password")
        #create_restricted_table("RestrictedData")
        #limit_user_data_access(123)  # Example user ID
        pass
    except Exception as e:
        print(f"Error during setup: {e}")

    app.run(debug=True)  #  Disable debug mode in production!

