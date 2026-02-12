from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Replace with your database URL
    DATABASE_URL = "postgresql://user:password@host:port/database"

    engine = create_engine(DATABASE_URL, pool_size=5, max_overflow=10)  # Configure connection pool
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Use the session in your routes
    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Example route
    @app.route('/users')
    def list_users():
        db = next(get_db())
        users = db.query(User).all()  # Assuming you have a User model
        return render_template('users.html', users=users)

