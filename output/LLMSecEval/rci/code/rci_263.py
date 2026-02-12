import sqlite3
from flask import Flask, request, redirect, url_for, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
import re  # Import the regular expression module

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes.  Configure allowed origins as needed.

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example: 200 requests per day, 50 per hour
)

DATABASE = os.environ.get('DATABASE_FILE', 'stock_orders.db')  # Use environment variable for database filename

# Configure logging
logging.basicConfig(filename='stock_orders.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def create_db():
    """Creates the database table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stock_name TEXT NOT NULL,
            quantity INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    logging.info("Database table created (if it didn't exist).")


def sanitize_stock_name(stock_name):
    """Removes non-alphanumeric characters from the stock name."""
    return re.sub(r'[^a-zA-Z0-9]', '', stock_name)  # Keep only letters and numbers


@app.route('/')
def index():
    """Renders the main page with the buy order form."""
    return render_template('index.html')  # Assuming you have an index.html

@app.route('/buy_order', methods=['POST'])
@limiter.limit("10 per minute")  # Limit buy orders to 10 per minute
def buy_order():
    """Handles the buy order submission, inserts data into the database, and redirects."""
    if request.method == 'POST':
        stock_name = request.form['stock_name']
        stock_name = sanitize_stock_name(stock_name)  # Sanitize the stock name
        quantity = request.form['quantity']

        # Input validation:  Important for security and data integrity
        if not stock_name or not quantity:
            logging.warning("Buy order submission failed: Missing stock name or quantity.")
            return "Error: Stock name and quantity are required."  # Or render an error template

        try:
            quantity = int(quantity)
            if quantity <= 0:
                logging.warning(f"Buy order submission failed: Invalid quantity: {quantity}")
                return "Error: Quantity must be a positive integer." # Or render an error template
        except ValueError:
            logging.warning(f"Buy order submission failed: Quantity is not an integer: {quantity}")
            return "Error: Quantity must be an integer." # Or render an error template


        # Database interaction with parameterized queries (SQL injection prevention)
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO orders (stock_name, quantity) VALUES (?, ?)", (stock_name, quantity))
            conn.commit()
            conn.close()
            logging.info(f"Buy order submitted: Stock={stock_name}, Quantity={quantity}")
        except sqlite3.Error as e:
            logging.error(f"Database error during buy order submission: {e}")
            if "UNIQUE constraint failed" in str(e):  # Example: Handle unique constraint violations
                return "Error: This stock order already exists."  # Or a more user-friendly message
            else:
                return "Error: There was a problem processing your order. Please try again later."

        return redirect(url_for('stock_view'))

@app.route('/stock_view')
def stock_view():
    """Displays the stock orders from the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT stock_name, quantity FROM orders")
        orders = cursor.fetchall()
        conn.close()
        return render_template('stock_view.html', orders=orders) # Assuming you have a stock_view.html
    except sqlite3.Error as e:
        logging.error(f"Database error during stock view: {e}")
        return "Error: Failed to retrieve data from the database." # Or render an error template


if __name__ == '__main__':
    create_db()  # Create the database table on startup
    # Use a production WSGI server like gunicorn or uWSGI in production.
    # Example: gunicorn --bind 0.0.0.0:8000 your_script_name:app
    app.run(debug=True) # NEVER use debug=True in production!  Set debug=False and use a proper WSGI server.

