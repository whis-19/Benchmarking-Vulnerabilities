import logging

logging.basicConfig(filename='app.log', level=logging.ERROR)  # Configure logging

def insert_user_message_in_db(username, message):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
        return True
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f"Database error: {e}", exc_info=True)  # Log the error with traceback
        return False
    finally:
        cur.close()

