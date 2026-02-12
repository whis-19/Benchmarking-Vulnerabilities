import logging

    logging.basicConfig(filename='app.log', level=logging.ERROR)

    try:
        # ... database operation ...
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        flash("An error occurred. Please try again later.")  # Generic message to the user

