if __name__ == '__main__':
    try:
        create_db_connection_pool()
        create_files_table()  # Create the table on startup
        app.run(debug=False)
    except Exception as e:
        logger.critical(f"Application failed to start: {e}")

