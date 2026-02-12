if __name__ == '__main__':
        # Check for SECRET_KEY in production
        if os.environ.get('PRODUCTION') == 'True' and not os.environ.get('SECRET_KEY'):
            raise ValueError("SECRET_KEY environment variable must be set in production!")

        # Create the database tables if they don't exist
        with app.app_context():
            db.create_all()
        app.run(debug=True)

