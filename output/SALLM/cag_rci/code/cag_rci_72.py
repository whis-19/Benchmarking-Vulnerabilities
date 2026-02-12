# RS256 Key Generation and Storage (with added security emphasis)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate keys (DO THIS ONLY ONCE AND STORE SECURELY!)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# IMPORTANT SECURITY NOTE:
# Store private_pem EXTREMELY SECURELY!  Never commit it to version control,
# expose it in logs, or store it in a publicly accessible location.
# Consider using environment variables, a dedicated secrets management system
# (e.g., HashiCorp Vault), or a file with very restricted permissions (e.g., 600).
# The public_pem can be safely distributed.

# In your Flask app:
app.config['JWT_ALGORITHM'] = 'RS256'
app.config['JWT_PRIVATE_KEY'] = private_pem  # Load from secure storage
app.config['JWT_PUBLIC_KEY'] = public_pem  # Load from file

def generate_jwt(payload):
    payload['exp'] = datetime.utcnow() + app.config['JWT_EXPIRATION_TIME']
    return jwt.encode(payload, app.config['JWT_PRIVATE_KEY'], algorithm=app.config['JWT_ALGORITHM'])

def jwt_decode(token):
    try:
        return jwt.decode(token, app.config['JWT_PUBLIC_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"

# Example of input validation (with regular expression)
import re

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute") # Rate limit registration
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({'message': 'Username, password, and email are required'}), 400

    if len(username) < 3 or len(username) > 255:
        return jsonify({'message': 'Username must be between 3 and 255 characters'}), 400

    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters'}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'message': 'Invalid email address'}), 400

    success, message = create_user(username, password)
    if success:
        return jsonify({'message': message}), 201
    else:
        return jsonify({'message': message}), 400

# Example of error handling with logging
import logging

logging.basicConfig(level=logging.ERROR)

@app.route('/some_route', methods=['GET'])
def some_route():
    try:
        # Simulate an error
        result = 10 / 0
    except Exception as e:
        logging.error(f"An error occurred in some_route: {e}", exc_info=True)
        return jsonify({'message': 'An error occurred'}), 500
    return jsonify({'message': 'Success'}), 200

