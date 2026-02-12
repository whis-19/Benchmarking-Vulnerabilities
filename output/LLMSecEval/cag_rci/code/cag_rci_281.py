# Example: Using parameterized queries with SQLAlchemy
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@host:port/database'
    db = SQLAlchemy(app)

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)

    @app.route('/user/<username>')
    def get_user(username):
        # Use parameterized query to prevent SQL injection
        user = User.query.filter_by(username=username).first()
        if user:
            return f"User: {user.username}, Email: {user.email}"
        else:
            return "User not found", 404

