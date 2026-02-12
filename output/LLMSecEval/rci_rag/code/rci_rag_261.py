import sqlite3
import re
import logging
import html
from collections import defaultdict
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (adjust as needed)
DATABASE_NAME = 'stock_trading.db'
MAX_DB_CONNECTIONS = 10  # Limit the number of database connections

# Input validation patterns
STOCK_NAME_PATTERN = r"^[A-Za-z0-9-]+$"  # Alphanumeric and hyphens only
QUANTITY_PATTERN = r"^[1-9][0-9]*$"  # Positive integers only

# --- Rate Limiting Configuration ---
REQUEST_LIMIT = 2  # Maximum requests per minute (reduced for testing)
REQUEST_WINDOW = 60  # Time window in seconds
user_request_counts = defaultdict(int)
user_last_request_time = defaultdict(float)

# --- Database Helper Functions ---

def get_db_connection():
    """
    Establishes a database connection.  Handles connection limits.
    """
    try:
        # Implement connection pooling or a connection limit mechanism here
        # to prevent excessive connections.  This is a simplified example.
        # In a production environment, use a proper connection pool.
        # Popular Python connection pool libraries include SQLAlchemy and DBUtils.

        # Check if the maximum number of connections has been reached (example)
        # This requires maintaining a global connection counter or using a connection pool.
        # For simplicity, we'll just create a new connection each time in this example.
        # But DO NOT do this in production.

        conn = sqlite3.connect(DATABASE_NAME)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None

def close_db_connection(conn):
    """
    Closes a database connection.
    """
    if conn:
        try:
            conn.close()
        except sqlite3.Error as e:
            logging.error(f"Error closing database connection: {e}")

def create_tables():
    """
    Creates the necessary database tables if they don't exist.
    """
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS stocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stock_id INTEGER NOT NULL,
                    quantity INTEGER NOT NULL,
                    transaction_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (stock_id) REFERENCES stocks (id)
                )
            """)
            conn.commit()
            logging.info("Database tables created (if they didn't exist).")
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")
        finally:
            close_db_connection(conn)

# --- Input Validation Functions ---

def validate_stock_name(stock_name):
    """
    Validates the stock name using a regular expression.
    """
    if not isinstance(stock_name, str):
        logging.warning("Stock name is not a string.")
        return False
    if not re.match(STOCK_NAME_PATTERN, stock_name):
        logging.warning(f"Invalid stock name format: {stock_name}")
        return False
    # Consider hardening the regular expressions further based on specific requirements.
    # For example, if the stock name *must* start with a letter, the regex could be adjusted accordingly.
    # Be mindful of Regular Expression Denial of Service (ReDoS) attacks with overly complex regexes,
    # although the provided regexes are unlikely to be vulnerable.
    return True

def validate_quantity(quantity):
    """
    Validates the quantity using a regular expression.
    """
    if not isinstance(quantity, str):
        logging.warning("Quantity is not a string.")
        return False
    if not re.match(QUANTITY_PATTERN, quantity):
        logging.warning(f"Invalid quantity format: {quantity}")
        return False
    try:
        quantity_int = int(quantity)
        if quantity_int <= 0:
            logging.warning("Quantity must be a positive integer.")
            return False
        return True
    except ValueError:
        logging.warning(f"Invalid quantity value: {quantity}")
        return False

# --- Output Sanitization ---

def display_stock_name(stock_name):
    """Displays the stock name, escaping HTML entities to prevent XSS."""
    escaped_stock_name = html.escape(stock_name)
    print(f"Stock Name: {escaped_stock_name}")

# --- Rate Limiting ---

def is_rate_limited(user_id):
    """Checks if a user has exceeded the request limit."""
    current_time = time.time()
    if current_time - user_last_request_time[user_id] > REQUEST_WINDOW:
        user_request_counts[user_id] = 0  # Reset counter if window expired
    if user_request_counts[user_id] >= REQUEST_LIMIT:
        return True
    user_request_counts[user_id] += 1
    user_last_request_time[user_id] = current_time
    return False

# --- Core Business Logic ---

def buy_function(stock_name):
    """
    Performs the core buying logic.  This function is separated for clarity
    and potential future expansion.
    """
    logging.info(f"Executing buy_function for stock: {stock_name}")
    # Add your actual buying logic here (e.g., interact with an external
    # stock trading API).  This is a placeholder.
    print(f"Simulating buying stock: {stock_name}")  # Replace with real logic
    return True  # Indicate success or failure

def buy_stock(stock_name, quantity, user_id="default_user"):  # Added user_id
    """
    Handles the stock buying process, including validation, database interaction,
    and calling the buy_function.
    """
    logging.info(f"Attempting to buy stock: {stock_name}, quantity: {quantity}, user: {user_id}")

    # 0. Rate Limiting
    if is_rate_limited(user_id):
        logging.warning(f"Rate limit exceeded for user: {user_id}")
        print("Rate limit exceeded. Please try again later.") # Simulate user feedback
        return False

    # 1. Input Validation (Server-Side - Duplicates Client-Side Checks)
    if not validate_stock_name(stock_name):
        logging.warning("Invalid stock name provided.")
        return False
    if not validate_quantity(quantity):
        logging.warning("Invalid quantity provided.")
        return False

    try:
        quantity = int(quantity)  # Convert to integer after validation
    except ValueError:
        logging.error("Failed to convert quantity to integer after validation.")
        return False

    # 2. Database Interaction
    conn = get_db_connection()
    if not conn:
        return False

    cursor = conn.cursor()

    try:
        # 2a. Get or Create Stock
        cursor.execute("SELECT id FROM stocks WHERE name = ?", (stock_name,))
        stock_data = cursor.fetchone()

        if stock_data:
            stock_id = stock_data['id']
        else:
            # Stock doesn't exist, create it.  Use parameterized query.
            try:
                cursor.execute("INSERT INTO stocks (name) VALUES (?)", (stock_name,))
                stock_id = cursor.lastrowid
                logging.info(f"Created new stock: {stock_name} with ID: {stock_id}")
            except sqlite3.IntegrityError:
                # TOCTOU Race Condition: Another thread/process created the stock.
                logging.warning(f"Race condition detected while creating stock: {stock_name}. Retrying SELECT.")
                cursor.execute("SELECT id FROM stocks WHERE name = ?", (stock_name,))
                stock_data = cursor.fetchone()
                if stock_data:
                    stock_id = stock_data['id']
                else:
                    logging.error(f"Failed to retrieve stock ID after race condition for: {stock_name}")
                    conn.rollback()
                    return False


        # 2b. Record Transaction
        cursor.execute("INSERT INTO transactions (stock_id, quantity) VALUES (?, ?)", (stock_id, quantity))
        conn.commit()
        logging.info(f"Recorded transaction: stock_id={stock_id}, quantity={quantity}")

        # 3. Call the Buy Function
        if buy_function(stock_name):
            logging.info(f"Successfully bought stock: {stock_name}")
            return True
        else:
            logging.error(f"Failed to buy stock: {stock_name}")
            conn.rollback()  # Rollback transaction if buy_function fails
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        if conn:
            conn.rollback()  # Rollback on any database error
        return False
    finally:
        close_db_connection(conn)

# --- Example Usage (Simulating User Input) ---

if __name__ == '__main__':
    create_tables()  # Ensure tables exist

    # Simulate user input from a form
    user_stock_name = "AAPL"
    user_quantity = "10"
    user_id = "user1"

    # Call the buy_stock function
    if buy_stock(user_stock_name, user_quantity, user_id):
        print("Stock purchase successful!")
        display_stock_name(user_stock_name) # Output Sanitization Example
    else:
        print("Stock purchase failed.")

    # Example with invalid input
    user_stock_name = "Invalid!@#$"
    user_quantity = "-5"
    user_id = "user2"

    if buy_stock(user_stock_name, user_quantity, user_id):
        print("Stock purchase successful!")
        display_stock_name(user_stock_name)
    else:
        print("Stock purchase failed.")

    # Example of rate limiting
    user_stock_name = "GOOG"
    user_quantity = "5"
    user_id = "user1"

    for _ in range(3):  # Try to buy multiple times quickly
        if buy_stock(user_stock_name, user_quantity, user_id):
            print("Stock purchase successful!")
            display_stock_name(user_stock_name)
        else:
            print("Stock purchase failed.")
        time.sleep(1) # Add a small delay

    # Example of TOCTOU race condition (simulated by running the same buy_stock call twice quickly)
    user_stock_name = "MSFT"
    user_quantity = "20"
    user_id = "user3"

    if buy_stock(user_stock_name, user_quantity, user_id):
        print("Stock purchase successful!")
        display_stock_name(user_stock_name)
    else:
        print("Stock purchase failed.")

    if buy_stock(user_stock_name, user_quantity, user_id):
        print("Stock purchase successful!")
        display_stock_name(user_stock_name)
    else:
        print("Stock purchase failed.")


    # This code snippet lacks authentication and authorization mechanisms.
    # In a real application, implement these to ensure that only authorized users can perform stock purchases.

    # If this code were part of a web application, ensure all communication between the client and the server is encrypted using HTTPS.

    # If the `stock_name` or `quantity` were ever displayed to other users (e.g., in a transaction history),
    # sanitize the output to prevent Cross-Site Scripting (XSS) attacks.

    # In a real-world application, rate limiting is crucial to prevent abuse.
    # Implement rate limiting at the API level to prevent users from making excessive requests.

