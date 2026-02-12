import sqlite3
import re
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (adjust as needed)
DATABASE_NAME = 'stock_trading.db'
MAX_DB_CONNECTIONS = 5  # Limit the number of database connections (not enforced in this example)

# Input validation patterns
# Matches alphanumeric stock names (e.g., AAPL, GOOG123)
STOCK_NAME_PATTERN = r"^[A-Za-z0-9]+$"
# Matches positive integers for quantity (e.g., 1, 10, 100)
QUANTITY_PATTERN = r"^[1-9][0-9]*$"

# --- Database Helper Functions ---

def get_db_connection():
    """
    Establishes a database connection.
    This version does NOT enforce the connection limit.  A connection pool
    or semaphore would be needed for that.
    """
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None


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
            logging.info("Database tables created/verified.")
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")
        finally:
            if conn:
                conn.close()

# Initialize the database tables
create_tables()


# --- Input Validation Functions ---

def validate_stock_name(stock_name):
    """
    Validates the stock name using a regular expression.
    """
    if not isinstance(stock_name, str):
        return False, "Stock name must be a string."
    if not re.match(STOCK_NAME_PATTERN, stock_name):
        return False, "Invalid stock name.  Must be alphanumeric."
    return True, None

def validate_quantity(quantity):
    """
    Validates the quantity using a regular expression.
    """
    if not isinstance(quantity, str):
        return False, "Quantity must be a string."
    if not re.match(QUANTITY_PATTERN, quantity):
        return False, "Invalid quantity. Must be a positive integer."
    try:
        quantity_int = int(quantity)
        if quantity_int > 10000: #Example limit
            return False, "Quantity exceeds maximum allowed (10000)."
        # Explicit check after conversion to ensure integer value is reasonable
        if quantity_int <= 0:
            return False, "Quantity must be a positive integer."
        return True, None
    except ValueError:
        return False, "Invalid quantity. Must be an integer."


# --- Core Functions ---

def buy_function(stock_name):
    """
    Buys the specified stock.  This function only handles the stock name.
    """
    try:
        with sqlite3.connect(DATABASE_NAME) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Use INSERT OR IGNORE to simplify the logic
            cursor.execute("INSERT OR IGNORE INTO stocks (name) VALUES (?)", (stock_name,))
            cursor.execute("SELECT id FROM stocks WHERE name = ?", (stock_name,))
            stock = cursor.fetchone()

            if stock:
                stock_id = stock['id']
                logging.info(f"Stock '{stock_name}' already exists (ID: {stock_id}) or was just created.")
                conn.commit() # Commit after INSERT OR IGNORE
                return True, stock_id  # Return the stock ID for further processing
            else:
                logging.error(f"Failed to retrieve stock ID for '{stock_name}' after INSERT OR IGNORE.")
                conn.rollback()
                return False, "Failed to retrieve stock ID."


    except sqlite3.Error as e:
        logging.error(f"Error in buy_function: {e}")
        if 'conn' in locals():  # Check if conn is defined before attempting rollback
            conn.rollback()
        return False, "An error occurred while processing the stock purchase. Please try again later." # User-friendly message


def buy_stock(stock_name, quantity):
    """
    Handles the purchase of a stock, including validation and database interaction.
    """

    # 1. Input Validation (Server-Side)
    stock_name_valid, stock_name_error = validate_stock_name(stock_name)
    quantity_valid, quantity_error = validate_quantity(quantity)

    if not stock_name_valid:
        return False, stock_name_error
    if not quantity_valid:
        return False, quantity_error

    # Convert quantity to integer after validation
    quantity = int(quantity)

    # 2. Call buy_function to handle stock name (and potentially create the stock)
    buy_result, stock_id_or_error = buy_function(stock_name)

    if not buy_result:
        return False, stock_id_or_error  # Propagate the error from buy_function

    stock_id = stock_id_or_error # Extract the stock ID

    # 3. Insert the transaction into the database
    try:
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO transactions (stock_id, quantity) VALUES (?, ?)", (stock_id, quantity))
            conn.commit()
            logging.info(f"Transaction recorded: Stock ID {stock_id}, Quantity {quantity}")
            return True, "Stock purchased successfully."

    except sqlite3.Error as e:
        logging.error(f"Error inserting transaction: {e}")
        if 'conn' in locals():
            conn.rollback()
        return False, "An error occurred while processing your purchase. Please try again later." # User-friendly message


# --- Example Usage (for testing) ---
if __name__ == '__main__':
    # Example 1: Valid purchase
    success, message = buy_stock("AAPL", "10")
    if success:
        print(f"Success: {message}")
    else:
        print(f"Error: {message}")

    # Example 2: Invalid stock name
    success, message = buy_stock("APPL!", "5")
    if success:
        print(f"Success: {message}")
    else:
        print(f"Error: {message}")

    # Example 3: Invalid quantity
    success, message = buy_stock("GOOG", "abc")
    if success:
        print(f"Success: {message}")
    else:
        print(f"Error: {message}")

    # Example 4: SQL Injection attempt (should be prevented)
    success, message = buy_stock("'; DROP TABLE transactions; --", "1")
    if success:
        print(f"Success: {message}")
    else:
        print(f"Error: {message}")

    # Example 5: Test with context managers
    success, message = buy_stock("MSFT", "100")
    if success:
        print(f"Success: {message}")
    else:
        print(f"Error: {message}")

    # Example 6: Test with zero quantity
    success, message = buy_stock("ZERO", "0")
    if success:
        print(f"Success: {message}")
    else:
        print(f"Error: {message}")

