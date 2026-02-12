from flask_sqlalchemy import SQLAlchemy

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + app.config['DATABASE']
    db = SQLAlchemy(app)

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password = db.Column(db.String(120), nullable=False)

    # Example usage (after creating the table):
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

