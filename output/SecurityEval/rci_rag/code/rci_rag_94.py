from flask import Flask, request, Response
import lxml.etree
import hashlib
import os
from functools import wraps
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from lxml import etree  # Import for schema validation
from flask_talisman import Talisman
import secrets
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configure Talisman for security headers
# Read configuration from environment variables
csp_directives = {
    'default-src': '\'self\'',
    'img-src': '*',  # Adjust as needed
    'script-src': '\'self\'',  # Adjust as needed
    'style-src': '\'self\'',  # Adjust as needed
    'font-src': '\'self\' data:', # Allow fonts from self and data URIs
    'object-src': '\'none\'', # Disable embedding plugins like Flash
}

# Enable HTTPS only in production
force_https = os.getenv("FLASK_ENV") == "production"

talisman = Talisman(
    app,
    content_security_policy=csp_directives,
    content_security_policy_nonce_in=['script-src'],
    force_https=force_https,
    session_cookie_secure=force_https,  # Only enable if using sessions
    session_cookie_httponly=True,
    frame_options='DENY', # Prevent clickjacking
    x_content_type_options='nosniff', # Prevent MIME sniffing
    referrer_policy='strict-origin-when-cross-origin', # Control referrer information
    hsts_max_age=31536000, # HSTS for one year
    hsts_include_subdomains=True,
    hsts_preload=True,
)


# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR)

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")  # Default to SQLite for development
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    userid = Column(String(50), unique=True, nullable=False)
    password_hash = Column(LargeBinary, nullable=False)
    salt = Column(LargeBinary, nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Adjust limits as needed
)


def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust for security/performance)
    )


def create_user(userid, password):
    """Creates a new user and stores the password hash in the database."""
    salt = secrets.token_bytes(16)  # Use secrets for cryptographically secure random salt
    password_hash = hash_password(password, salt)

    session = Session()
    try:
        new_user = User(userid=userid, password_hash=password_hash, salt=salt)
        session.add(new_user)
        session.commit()
    except sqlalchemy.exc.IntegrityError:
        session.rollback()
        return False, "Username already exists" # Handle duplicate usernames
    finally:
        session.close()
    return True, None


def check_password(userid, password):
    """Checks if the provided password matches the stored hash in the database."""
    session = Session()
    try:
        user = session.query(User).filter_by(userid=userid).first()
        if not user:
            return False

        stored_password_hash = user.password_hash
        salt = user.salt
        password_hash = hash_password(password, salt)

        return password_hash == stored_password_hash
    finally:
        session.close()


def requires_auth(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_password(auth.username, auth.password):
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated


def validate_xml(xml_content, schema_file):
    """Validates XML content against an XSD schema."""
    try:
        xmlschema_doc = etree.parse(schema_file)
        xmlschema = etree.XMLSchema(xmlschema_doc)
        xml_doc = etree.fromstring(xml_content)
        xmlschema.assertValid(xml_doc)
        return True
    except etree.XMLSchemaError as e:
        logging.error(f"Schema validation error: {e}")
        return False
    except etree.XMLSyntaxError as e:
        logging.error(f"XML syntax error: {e}")
        return False
    except Exception as e:
        logging.exception("An unexpected error occurred during schema validation:")
        return False


@app.post("/upload")
@requires_auth
@limiter.limit("5 per minute")  # Limit upload attempts
def upload():
    """
    Gets the XML file from the request and checks authentication.
    """
    try:
        xml_file = request.files['file']
        xml_content = xml_file.read()

        # Disable DTD processing and external entity resolution
        parser = lxml.etree.XMLParser(
            dtd_validation=False,
            resolve_entities=False,
            no_network=True  # Important: Prevents network access for includes
        )

        # Parse the XML content
        try:
            root = lxml.etree.fromstring(xml_content, parser=parser)

            # **VALIDATE XML AGAINST SCHEMA**
            schema_file_path = os.getenv("XML_SCHEMA_PATH", "your_schema.xsd") # Get schema path from env
            if not validate_xml(xml_content, schema_file_path):  # Replace with your schema file
                return "XML validation failed", 400

            # Process the XML data here (e.g., extract information, validate structure)
            # Example:
            # for element in root.iter():
            #     print(element.tag, element.text)

            return "XML uploaded and processed successfully."

        except lxml.etree.XMLSyntaxError as e:
            logging.error(f"XML parsing error: {e}")
            return "XML parsing error", 400

    except KeyError:
        return "No file part in the request", 400
    except Exception as e:
        logging.exception("An error occurred during upload:")
        return "An unexpected error occurred.", 500


if __name__ == '__main__':
    # Example: Create a default user (replace with a proper user registration)
    with app.app_context():
        success, message = create_user("testuser", "password123")  # NEVER hardcode credentials in production!
        if not success:
            print(f"Failed to create user: {message}")

    # DO NOT USE debug=True IN PRODUCTION!
    # HTTPS is required in production
    app.run(debug=True, host="0.0.0.0", port=5000) # Listen on all interfaces

