import os
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv
import logging
import bcrypt
import re  # Import the regular expression module
from psycopg2 import pool  # Import the connection pool module

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

# --- Helper Functions ---

def is_valid_hostname(hostname):
    """
    Validates that a hostname is a valid hostname or IP address.
    """
    if not isinstance(hostname, str):
        return False
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present

    # Allow IP addresses
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass  # Not an IP address, try hostname validation

    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# --- Database Connection Pool (Initialize at application startup) ---
# Consider adjusting the pool size based on your application's needs and database server capacity.
db_host = os.environ.get("DB_HOST")
db_name = os.environ.get("DB_NAME")
db_user = os.environ.get("DB_USER")
db_password = os.environ.get("DB_PASSWORD")
db_port_str = os.environ.get("DB_PORT")

if not all([db_host, db_name, db_user, db_password, db_port_str]):
    logging.error("Missing database credentials in environment variables.")
    # It's critical to raise an exception here, as the application cannot function without database access.
    raise ValueError("Missing database credentials in environment variables.")

try:
    db_port = int(db_port_str)
except ValueError:
    logging.error("DB_PORT must be an integer.")
    raise ValueError("DB_PORT must be an integer.")

if not is_valid_hostname(db_host):
    logging.error("DB_HOST is not a valid hostname or IP address.")
    raise ValueError("DB_HOST is not a valid hostname or IP address.")


try:
    db_pool = pool.SimpleConnectionPool(1, 20,  # min, max connections
                                        host=db_host,
                                        database=db_name,
                                        user=db_user,
                                        password=db_password,
                                        port=db_port)
    logging.info("Database connection pool initialized.")
except psycopg2.Error as e:
    logging.error(f"Failed to create connection pool: {e}")
    raise  # Re-raise the exception to prevent the application from starting without a database connection.


# --- Functions ---

def is_moderator(username):
    """
    Checks if a user is a moderator in the database.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if the user is a moderator, False otherwise.
    Raises:
        Exception: If a database error occurs.
    """
    conn = None
    cur = None
    try:
        conn = db_pool.getconn()  # Get a connection from the pool
        cur = conn.cursor()

        # Use parameterized query to prevent SQL injection
        query = sql.SQL("SELECT is_moderator FROM users WHERE username = %s").format()
        cur.execute(query, (username,))

        result = cur.fetchone()

        if result:
            return result[0]  # Assuming 'is_moderator' is a boolean column
        else:
            return False  # User not found or is_moderator is NULL

    except psycopg2.Error as e:
        logging.error(f"Database error: {e}")
        raise  # Re-raise the exception to be handled by the calling code
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full traceback
        raise  # Re-raise the exception
    finally:
        if cur:
            try:
                cur.close()
            except Exception as e:
                logging.error(f"Error closing cursor: {e}")
        if conn:
            db_pool.putconn(conn)  # Return the connection to the pool


def create_limited_user(new_username, new_password, db_admin_user, db_admin_password, db_name):
    """
    Creates a new database user with limited read-only access to specific tables.
    This function should be run with administrative privileges.
    Raises an exception on error.
    """
    conn = None
    cur = None
    try:
        db_host = os.environ.get("DB_HOST")
        db_port_str = os.environ.get("DB_PORT")

        if not all([db_host, db_admin_user, db_admin_password, db_name, db_port_str]):
            logging.error("Missing database credentials in environment variables for create_limited_user.")
            raise ValueError("Missing database credentials in environment variables.")

        # Validate environment variables
        try:
            db_port = int(db_port_str)
        except ValueError:
            logging.error("DB_PORT must be an integer.")
            raise ValueError("DB_PORT must be an integer.")

        # Validate DB_HOST
        if not is_valid_hostname(db_host):
            logging.error("DB_HOST is not a valid hostname or IP address.")
            raise ValueError("DB_HOST is not a valid hostname or IP address.")

        # Validate db_name against a whitelist (if it could come from an untrusted source)
        allowed_db_names = ["mydatabase", "anotherdatabase"]  # Replace with your allowed names
        if db_name not in allowed_db_names:
            logging.error(f"Invalid database name: {db_name}.  Must be one of: {allowed_db_names}")
            raise ValueError(f"Invalid database name: {db_name}.  Must be one of: {allowed_db_names}")

        # Password complexity check
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[a-z]", new_password):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"[A-Z]", new_password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"\d", new_password):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
            raise ValueError("Password must contain at least one special character.")


        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_admin_user,
            password=db_admin_password,
            port=db_port
        )
        conn.autocommit = True  # Required for CREATE ROLE/USER.  Be aware of the security implications.

        cur = conn.cursor()

        # Hash the password using bcrypt
        hashed_password = hash_password(new_password)

        # Create the user with a password (hash the password in a real application!)
        create_user_sql = sql.SQL("CREATE USER {} WITH PASSWORD %s").format(sql.Identifier(new_username))
        cur.execute(create_user_sql, (hashed_password,))

        # Grant CONNECT privilege to the database
        grant_connect_sql = sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(db_name), sql.Identifier(new_username)
        )
        cur.execute(grant_connect_sql)

        # Grant SELECT privilege to specific tables (e.g., 'users' table)
        grant_select_sql = sql.SQL("GRANT SELECT ON TABLE users TO {}").format(sql.Identifier(new_username))
        cur.execute(grant_select_sql)

        # Revoke all other privileges (important for least privilege)
        # REVOKE ALL PRIVILEGES can cause issues with connect or select if not granted explicitly.
        # Revoke individually as needed.
        # Example of revoking specific privileges:
        # revoke_usage_sql = sql.SQL("REVOKE USAGE ON SCHEMA public FROM {}").format(sql.Identifier(new_username))
        # cur.execute(revoke_usage_sql)


        print(f"User '{new_username}' created with limited privileges.")
        logging.info(f"User '{new_username}' created with limited privileges.")


    except psycopg2.Error as e:
        logging.error(f"Error creating user: {e}")
        raise  # Re-raise the exception
    except Exception as e:
        logging.exception("Error creating user:")
        raise  # Re-raise the exception
    finally:
        if cur:
            try:
                cur.close()
            except Exception as e:
                logging.error(f"Error closing cursor: {e}")
        if conn:
            try:
                conn.close()
            except Exception as e:
                logging.error(f"Error closing connection: {e}")


if __name__ == '__main__':
    # Example usage (replace with actual username)
    username_to_check = "testuser"  # Replace with a valid username from your database
    try:
        is_mod = is_moderator(username_to_check)

        if is_mod:
            print(f"User '{username_to_check}' is a moderator.")
        else:
            print(f"User '{username_to_check}' is not a moderator.")
    except Exception as e:
        print(f"Error checking moderator status: {e}")


# Example usage of create_limited_user (run this separately and only with appropriate admin credentials)
# WARNING:  Running this without proper credentials or with invalid parameters can lead to errors or security vulnerabilities.
# try:
#     create_limited_user("readonlyuser", "StrongPwd123!", os.environ.get("DB_ADMIN_USER"), os.environ.get("DB_ADMIN_PASSWORD"), os.environ.get("DB_NAME"))
# except Exception as e:
#     print(f"Error creating limited user: {e}")

