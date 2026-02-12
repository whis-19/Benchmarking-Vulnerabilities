from werkzeug.security import safe_str_cmp

    # ... inside the login route, after retrieving the stored hash ...
    # Assuming 'stored_hash' is retrieved from the database
    if user_data and check_password(password, stored_hash):
        # ... login successful ...
        pass
    else:
        # ... login failed ...
        pass

