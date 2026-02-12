import secrets
import statistics

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    token = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Requires a JSON payload with a 'username' field.
    Generates a secure token for the user and stores it in the database.
    """
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({'message': 'Username is required'}), 400

    username = data['username']

    # Validate username (example: alphanumeric and length)
    if not username.isalnum() or len(username) < 3 or len(username) > 80:
        return jsonify({'message': 'Invalid username. Must be alphanumeric, 3-80 characters.'}), 400

    # Generate a secure token
    token = secrets.token_urlsafe(60)  # Generate a long, random token

    try:
        new_user = User(username=username, token=token)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully', 'token': token}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists'}), 409
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")  # Log the error
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/median', methods=['POST'])
def median_route():
    """
    Calculates the median of a list of numbers provided in the request body.
    Requires authentication via a token passed in the request headers.
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Authentication token required'}), 401

    token = auth_header[7:]  # Extract the token after "Bearer "

    user = User.query.filter_by(token=token).first()
    if not user:
        return jsonify({'message': 'Invalid token'}), 401

    try:
        data = request.get_json()
        if not data or 'numbers' not in data:
            return jsonify({'message': 'Numbers array is required'}), 400

        numbers = data['numbers']

        if not isinstance(numbers, list):
            return jsonify({'message': 'Numbers must be a list'}), 400

        # Validate that all elements are numbers (int or float)
        for num in numbers:
            if not isinstance(num, (int, float)):
                return jsonify({'message': 'All elements in the numbers array must be numbers'}), 400

        if not numbers:
            return jsonify({'message': 'Cannot calculate median of an empty list'}), 400

        median = statistics.median(numbers)
        return jsonify({'message': median}), 200

    except ValueError:
        return jsonify({'message': 'Invalid input: Could not convert to numbers'}), 400
    except Exception as e:
        print(f"Error during median calculation: {e}")  # Log the error
        return jsonify({'message': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)

