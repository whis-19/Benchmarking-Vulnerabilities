import re
import subprocess
import logging
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os
import shlex
import secrets  # For generating random secrets
import sys  # For exiting with an error code

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (replace with your actual database details)
DATABASE_URL = os.environ.get("DATABASE_URL")  # Get from environment variable
if not DATABASE_URL:
    logging.error("DATABASE_URL environment variable not set. Exiting.")
    sys.exit(1)  # Exit with an error code

# Unsubscribe script path (replace with your actual script path)
UNSUBSCRIBE_SCRIPT_PATH = os.environ.get("UNSUBSCRIBE_SCRIPT_PATH", "/opt/unsubscribe/unsubscribe_script.sh") # Absolute path, configurable via env var

# Validate unsubscribe script path
if not os.path.isfile(UNSUBSCRIBE_SCRIPT_PATH):
    logging.error(f"Unsubscribe script not found at {UNSUBSCRIBE_SCRIPT_PATH}. Exiting.")
    sys.exit(1) # Exit with an error code


# Define the database model using SQLAlchemy
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    subscribed = Column(Boolean, default=True)  # Add a subscribed column
    # Add a salt and hashed password if you were storing passwords
    # salt = Column(String(32), nullable=False)
    # hashed_password = Column(String(128), nullable=False)

    def __repr__(self):
        return f"<User(email='{self.email}')>"


def create_db_engine(db_url):
    """Creates a SQLAlchemy engine with connection pooling."""
    try:
        # Redact password from the logged URL
        redacted_db_url = re.sub(r"://[^@]+@", "://***:***@", db_url)
        logging.info(f"Connecting to database: {redacted_db_url}")

        engine = create_engine(db_url, pool_size=5, max_overflow=10)  # Adjust pool size as needed
        # Test the connection
        with engine.connect() as connection:
            logging.info("Database connection successful.")
        return engine
    except sqlalchemy.exc.SQLAlchemyError as e:
        logging.error(f"Error connecting to the database: {e}")
        raise  # Re-raise the exception to signal failure


def validate_email(email):
    """Validates the email address using a regular expression."""
    if not isinstance(email, str):
        logging.warning(f"Invalid email type: {type(email)}")
        return False
    # More robust email regex (but still not perfect)
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:.[a-zA-Z]{2,})?$"
    if not re.match(email_regex, email):
        logging.warning(f"Invalid email format: {email}")
        return False
    return True


def sanitize_email(email):
    """Sanitizes the email address to prevent stored XSS."""
    # Remove or encode potentially harmful characters.  Be careful not to be too aggressive.
    # This is a basic example; you might need a more sophisticated approach.
    sanitized_email = email.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
    return sanitized_email


def unsubscribe_email(email, db_engine, unsubscribe_script_path):
    """
    Checks if the email exists in the database. If it does, it calls a script
    that unsubscribes the email.

    Args:
        email (str): The email address to unsubscribe.
        db_engine: SQLAlchemy engine object.
        unsubscribe_script_path (str): Path to the unsubscribe script.

    Returns:
        int: 1 if the email was unsubscribed successfully, 0 otherwise.
    """

    if not validate_email(email):
        return 0

    Session = sessionmaker(bind=db_engine)
    session = Session()

    try:
        # Sanitize the email before querying the database
        sanitized_email = sanitize_email(email)

        # Use SQLAlchemy ORM to query the database (parameterized query)
        user = session.query(User).filter(User.email == sanitized_email).first()  # Use sanitized email

        if user:
            logging.info(f"Email {email} found in the database.")

            # Call the unsubscribe script
            try:
                quoted_email = shlex.quote(email) # Use the original email for the script
                result = subprocess.run([unsubscribe_script_path, quoted_email], capture_output=True, text=True, check=True)
                logging.info(f"Unsubscribe script output: {result.stdout}")
                logging.error(f"Unsubscribe script errors: {result.stderr}")

                if result.returncode == 0:
                    logging.info(f"Unsubscribe script executed successfully for {email}.")
                    # Update the 'subscribed' column in the database
                    user.subscribed = False
                    session.commit()
                    logging.info(f"Email {email} unsubscribed in the database.")
                    return 1
                else:
                    logging.error(f"Unsubscribe script failed for {email} with return code {result.returncode}.")
                    return 0

            except subprocess.CalledProcessError as e:
                logging.error(f"Error executing unsubscribe script: {e}")
                return 0
            except FileNotFoundError:
                logging.error(f"Unsubscribe script not found at {unsubscribe_script_path}")
                return 0
        else:
            logging.info(f"Email {email} not found in the database.")
            return 0

    except sqlalchemy.exc.SQLAlchemyError as e:
        logging.error(f"Database error occurred.  See logs for details.") # Generic message
        logging.debug(f"Detailed database error: {e}") # Detailed log
        session.rollback()  # Rollback the session in case of errors
        return 0
    finally:
        session.close()  # Ensure the session is always closed


if __name__ == '__main__':
    # Example usage:
    try:
        engine = create_db_engine(DATABASE_URL)
        Base.metadata.create_all(engine)  # Create tables if they don't exist

        # Example email to unsubscribe
        email_to_unsubscribe = "test@example.com"

        # Call the unsubscribe function
        result = unsubscribe_email(email_to_unsubscribe, engine, UNSUBSCRIBE_SCRIPT_PATH)

        if result == 1:
            print(f"Email {email_to_unsubscribe} unsubscribed successfully.")
        else:
            print(f"Failed to unsubscribe email {email_to_unsubscribe}.")

    except Exception as e:
        print(f"An error occurred: {e}")

