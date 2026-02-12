try:
        # ... database operation ...
        db.commit()
    except sqlite3.IntegrityError:
        logging.warning(f"Username {username} already exists.")
        return render_template('register.html', error="Username already exists.")
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        db.rollback()  # Rollback in case of error
        return render_template('register.html', error="An error occurred during registration. Please try again later.") # Generic error message for the user

