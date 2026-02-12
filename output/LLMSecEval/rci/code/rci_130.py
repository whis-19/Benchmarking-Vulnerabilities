if __name__ == '__main__':
        import logging
        logging.basicConfig(filename=app.config['ERROR_LOG'], level=logging.ERROR)
        create_db()  # Create the database table on startup
        app.run(debug=True)  # REMOVE debug=True FOR PRODUCTION!

