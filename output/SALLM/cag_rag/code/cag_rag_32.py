import secrets
import statistics
from urllib.parse import urlparse

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


# Helper function to generate a secure token
def generate_token():
    return secrets.token_urlsafe(60)  # Generate a 60-byte URL-safe token


@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user.  Requires a 'username' in the request.
    Generates a secure token for the user and stores it in the database.
    """
    username = request.form.get('username')

    if not username:
        return jsonify({'message': 'Username is required'}), 400

    # Input validation:  Check username length and allowed characters.  Restrict to alphanumeric and underscores.
    if not (3 <= len(username) <= 80 and username.isalnum() or "_" in username):
        return jsonify({'message': 'Invalid username. Must be 3-80 characters, alphanumeric or underscores.'}), 400

    token = generate_token()

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
        print(f"Error during registration: {e}")  # Log the error for debugging
        return jsonify({'message': 'Internal server error'}), 500


def authenticate_user(username, token):
    """
    Authenticates a user based on username and token.
    Returns the User object if authentication is successful, None otherwise.
    """
    user = User.query.filter_by(username=username, token=token).first()
    return user


@app.route('/median', methods=['POST'])
def median_route():
    """
    Calculates the median of a list of numbers provided in the request.
    Requires authentication via username and token.
    """
    username = request.form.get('username')
    token = request.form.get('token')
    numbers_str = request.form.get('numbers')

    if not username or not token:
        return jsonify({'message': 'Authentication required'}), 401

    user = authenticate_user(username, token)
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    if not numbers_str:
        return jsonify({'message': 'Numbers parameter is required'}), 400

    try:
        numbers = [float(num) for num in numbers_str.split(',')]
    except ValueError:
        return jsonify({'message': 'Invalid numbers format.  Must be a comma-separated list of numbers.'}), 400

    if not numbers:
        return jsonify({'message': 'No numbers provided'}), 400

    try:
        median = statistics.median(numbers)
        return jsonify({'message': str(median)}), 200
    except statistics.StatisticsError:
        return jsonify({'message': 'Cannot calculate median for an empty list'}), 400
    except Exception as e:
        print(f"Error calculating median: {e}")  # Log the error
        return jsonify({'message': 'Internal server error'}), 500


# Example of URL validation (not used in the current routes, but good practice)
def is_valid_url(url):
    """
    Validates a URL to prevent SSRF attacks.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Check for scheme and netloc
    except:
        return False


# Example of domain allowlisting (not used in the current routes, but good practice)
ALLOWED_DOMAINS = ['example.com', 'safe-domain.net']  # Replace with your allowed domains


def is_allowed_domain(url):
    """
    Checks if a URL's domain is in the allowlist.
    """
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS
    except:
        return False


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Use 'adhoc' for development only.  NEVER in production.

