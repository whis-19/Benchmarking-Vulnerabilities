import psycopg2
import logging
import os

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    # Retrieve database credentials from environment variables (more secure)
    db_host = os.environ.get("DB_HOST", "localhost")  # Default to localhost
    db_name = os.environ.get("DB_NAME", "mydatabase")
    db_user = os.environ.get("DB_USER", "myuser")
    db_password = os.environ.get("DB_PASSWORD", "mypassword")
    db_port = int(os.environ.get("DB_PORT", "5432"))  # Default to 5432

    conn = psycopg2.connect(database=db_name, user=db_user, password=db_password, host=db_host, port=db_port)
    cur = conn.cursor()

    username = input("Enter username: ")  # Get username from user input

    # Use a parameterized query to prevent SQL injection
    sql = "SELECT * FROM users WHERE username = %s"
    cur.execute(sql, (username,))

    rows = cur.fetchall()
    for row in rows:
        print(row)

    conn.commit()
    cur.close()
    conn.close()

except psycopg2.Error as e:
    logging.error("Database query error: %s", e)  # Log the error, but not the full exception
    print("An error occurred while querying the database.  Please contact support.") # User-friendly message
except Exception as e:
    logging.exception("General error: %s", e)  # Log the full exception for debugging
    print("An unexpected error occurred.  Please contact support.") # User-friendly message
finally:
    # Ensure the connection is closed, even if an error occurs
    if 'conn' in locals() and conn:
        try:
            cur.close()
            conn.close()
        except Exception as e:
            logging.error("Error closing connection: %s", e)

