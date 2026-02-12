import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # ...
    try:
        # ...
    except sqlite3.IntegrityError as e:
        logging.error(f"Registration error: {e}")
        flash('Username or email already exists.', 'error')
    except Exception as e:
        logging.error(f"Unexpected registration error: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')
    finally:
        conn.close()
    # ...

