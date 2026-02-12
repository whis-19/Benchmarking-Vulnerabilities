if __name__ == '__main__':
    db_host = "localhost"
    db_user = "your_user"

    try:
        connection = getDBConnection(db_host, db_user)

        if connection:
            # Example 1:  Safe insertion with parameterized query and input validation
            username = input("Enter username: ")
            email = input("Enter email: ")

            validated_username = validate_input(username, 'string', max_length=50, allowed_characters=r"^[a-zA-Z0-9_]+$") # Allow alphanumeric and underscore
            validated_email = validate_input(email, 'email', max_length=100)

            if validated_username and validated_email:
                # Sanitize for display (if needed)
                safe_username = html.escape(validated_username)
                safe_email = html.escape(validated_email)

                query = "INSERT INTO users (username, email) VALUES (%s, %s)"
                params = (validated_username, validated_email)
                result = execute_query(connection, query, params)
                if result is not None:
                    connection.commit()
                    print("User inserted successfully.")
                else:
                    print("Failed to insert user.")
                    logging.error("User insertion failed.")
            else:
                print("Invalid input. User insertion aborted.")

            connection.close()  # Close the connection
        else:
            print("Failed to connect to the database.")

    except Exception as e:
        print(f"An error occurred: {e}")
        logging.exception("An unhandled exception occurred.") # Log the full exception traceback

