import click
from flask import Flask
# ... your other imports ...

app = Flask(__name__)
# ... your app configuration ...

@app.cli.command("create-admin")
@click.argument("username")
@click.argument("password")
def create_admin(username, password):
    """Creates an admin user."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'admin'))
        db.commit()
        print(f"Admin user '{username}' created successfully.")
    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists.")
    finally:
        pass #close_db_connection(db)

# To run this: flask create-admin admin_username admin_password

