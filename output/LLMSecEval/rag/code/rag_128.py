import re
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration -  Use the strictest permissions possible on all database objects.
DATABASE_NAME = 'stock_trading.db'  # Consider environment variable for configuration
MAX_DB_CONNECTIONS = 10  # Limit the number of connections

# Input validation patterns
STOCK_NAME_PATTERN = r"^[a-zA-Z0-9]+$"  # Alphanumeric only
QUANTITY_PATTERN = r"^[1-9][0-9]*$"  # Positive integers only

def create_connection():
    """Creates a database connection with connection limiting."""
    try:
        conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)  # Consider thread safety if needed
        conn.row_factory = sqlite3.Row  # Access columns by name
        # Implement connection limiting (e.g., using a semaphore or connection pool)
        # This is a simplified example; a proper connection pool is recommended for production.
        # Example:
        # if len(active_connections) >= MAX_DB_CONNECTIONS:
        #     raise Exception("Too many database connections.")
        # active_connections.append(conn)
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None

def close_connection(conn):
    """Closes a database connection."""
    if conn:
        try:
            conn.close()
            # Remove from active connections (if using a connection pool)
            # active_connections.remove(conn)
        except sqlite3.Error as e:
            logging.error(f"Database closing error: {e}")

def is_valid_stock_name(stock_name):
    """Validates the stock name using a regular expression."""
    if not isinstance(stock_name, str):
        return False
    return bool(re.match(STOCK_NAME_PATTERN, stock_name))

def is_valid_quantity(quantity):
    """Validates the quantity using a regular expression."""
    if not isinstance(quantity, str): # Expecting string from form
        return False
    return bool(re.match(QUANTITY_PATTERN, quantity))

def buy_function(stock_name):
    """
    Buys the specified stock.  This function assumes the stock_name is already validated.
    """
    conn = create_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()

        # Example: Check if the stock exists (prevent SQL injection by using a parameterized query)
        cursor.execute("SELECT COUNT(*) FROM stocks WHERE stock_name = ?", (stock_name,))
        stock_exists = cursor.fetchone()[0]
        if stock_exists == 0:
            logging.warning(f"Stock {stock_name} does not exist.")
            return False

        # Example: Update the stock quantity (using a parameterized query)
        cursor.execute("UPDATE stocks SET quantity = quantity + 1 WHERE stock_name = ?", (stock_name,))
        conn.commit()
        logging.info(f"Bought stock: {stock_name}")
        return True

    except sqlite3.Error as e:
        logging.error(f"Database error during buy_function: {e}")
        conn.rollback()
        return False
    finally:
        close_connection(conn)


def buy_stock(stock_name, quantity):
    """
    Handles the purchase of a stock, including validation and database interaction.
    """
    # Server-side validation (duplicate client-side checks)
    if not isinstance(stock_name, str) or not isinstance(quantity, str):
        logging.warning("Invalid input types.")
        return False

    if not is_valid_stock_name(stock_name):
        logging.warning(f"Invalid stock name: {stock_name}")
        return False

    if not is_valid_quantity(quantity):
        logging.warning(f"Invalid quantity: {quantity}")
        return False

    try:
        quantity = int(quantity)  # Convert to integer after validation
    except ValueError:
        logging.error("Quantity could not be converted to an integer.")
        return False

    # Validate derived quantities (e.g., prevent excessively large quantities)
    if quantity > 10000:  # Example limit
        logging.warning("Quantity exceeds maximum allowed.")
        return False

    conn = create_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()

        # Insert the stock purchase into the database (using a parameterized query)
        cursor.execute(
            "INSERT INTO stock_purchases (stock_name, quantity) VALUES (?, ?)",
            (stock_name, quantity),
        )
        conn.commit()
        logging.info(f"Inserted purchase of {quantity} shares of {stock_name} into stock_purchases table.")

        # Call the buy_function to update the stock (validated stock_name is passed)
        if not buy_function(stock_name):
            logging.error(f"Failed to buy stock {stock_name} via buy_function.")
            conn.rollback()
            return False

        return True

    except sqlite3.Error as e:
        logging.error(f"Database error during buy_stock: {e}")
        conn.rollback()
        return False
    finally:
        close_connection(conn)


# Example usage (simulating form input)
if __name__ == '__main__':
    # Create a sample database and table (only for demonstration)
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stocks (
                stock_name TEXT PRIMARY KEY,
                quantity INTEGER
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stock_purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_name TEXT,
                quantity INTEGER
            )
        """)
        # Insert a sample stock
        cursor.execute("INSERT OR IGNORE INTO stocks (stock_name, quantity) VALUES (?, ?)", ("AAPL", 100))
        conn.commit()
        close_connection(conn)

    stock_name = "AAPL"  # Example stock name from form
    quantity = "10"  # Example quantity from form

    if buy_stock(stock_name, quantity):
        print("Stock purchase successful!")
    else:
        print("Stock purchase failed.")

    # Example of invalid input
    stock_name = "Invalid!@#$"
    quantity = "-5"
    if buy_stock(stock_name, quantity):
        print("Stock purchase successful!")
    else:
        print("Stock purchase failed.")

