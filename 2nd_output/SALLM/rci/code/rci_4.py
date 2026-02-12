import tempfile
import os
import secrets
import hashlib
import logging
import shutil  # For secure file deletion

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach  # For HTML sanitization (install with pip install bleach)

# Import your authentication library (e.g., Flask-Login)
# from flask_login import login_required, current_user

# Database imports (example using SQLAlchemy and SQLite)
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

app = Flask(__name__)

# Configure logging (example with file rotation)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log_file_handler = logging.handlers.RotatingFileHandler('app.log', maxBytes=1024*1024, backupCount=5) # 1MB, 5 backups
logging.getLogger('').addHandler(log_file_handler)


# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example: 200 requests per day, 50 per hour
)

# Secret key for session management (if you implement authentication)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Database configuration (SQLite example)
DATABASE_URL = "sqlite:///./file_hashes.db"  # Use a proper database in production
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class FileHash(Base):
    __tablename__ = "file_hashes"

    id = Column(Integer, primary_key=True)
    file_hash = Column(String, unique=True, nullable=False)
    file_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    # Add user_id column when authentication is implemented
    # user_id = Column(Integer, ForeignKey('users.id'))

Base.metadata.create_all(engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Temporary file directory
TEMP_DIR = "temp_files"
os.makedirs(TEMP_DIR, exist_ok=True)  # Create if it doesn't exist

def generate_file_hash(file_path):
    """Generates a SHA-256 hash of the file content."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


@app.route('/write_temp', methods=['POST'])
@limiter.limit("10/minute")  # Example: 10 requests per minute
#@login_required  # Uncomment after implementing authentication
def write_results():
    """
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return a hash of the file content instead of the path.
    """
    if request.content_type != 'application/json':
        logging.warning(f"Invalid Content-Type from {request.remote_addr}")
        return jsonify({'error': 'Invalid Content-Type.  Must be application/json'}), 400

    try:
        data = request.get_json()
        results = data.get('results')

        if not isinstance(results, str):
            logging.warning(f"Invalid results type from {request.remote_addr}")
            return jsonify({'error': 'Results must be a string'}), 400

        # Input validation:  Sanitize the input to prevent injection attacks.
        #  REPLACE WITH CONTEXT-AWARE SANITIZATION.  THIS IS CRITICAL.
        # Example using Bleach (install with pip install bleach)
        results = bleach.clean(results, tags=['p', 'b', 'i', 'a', 'br'], attributes={'a': ['href', 'title']}, strip=True)

        # Length Limit
        if len(results) > 10240:  # Example: Limit to 10KB
            logging.warning(f"Results too long from {request.remote_addr}")
            return jsonify({'error': 'Results too long (max 10KB)'}), 400


        # Secure temporary file creation
        random_prefix = secrets.token_hex(8)
        random_suffix = secrets.token_hex(8)

        # Create a secure temporary file with a unique name
        try:
            fd, temp_file_path = tempfile.mkstemp(prefix=f"{random_prefix}_", suffix=f"_{random_suffix}.txt", dir=TEMP_DIR, text=True)
            os.chmod(temp_file_path, 0o600)  # Set permissions immediately
        except OSError as e:
            logging.error(f"Error creating temporary file: {e}")
            return jsonify({'error': 'Failed to create temporary file'}), 500


        try:
            # Write the results to the temporary file with UTF-8 encoding
            with os.fdopen(fd, 'w', encoding='utf-8') as f:  # Use fd directly
                f.write(results)

            # Generate a hash of the file content
            file_hash = generate_file_hash(temp_file_path)

            # Store the file hash and path in the database
            db = SessionLocal()
            try:
                db_file_hash = FileHash(file_hash=file_hash, file_path=temp_file_path)
                db.add(db_file_hash)
                db.commit()
            except Exception as db_e:
                db.rollback()
                logging.error(f"Error writing to database: {db_e}")
                return jsonify({'error': 'Failed to write to database'}), 500
            finally:
                db.close()


            # Log success
            logging.info(f"File written successfully to {temp_file_path} from {request.remote_addr}, hash: {file_hash}")

            # Return the hash of the file content instead of the file path
            return jsonify({'file_hash': file_hash}), 200

        except Exception as e:
            logging.error(f"Error writing to temporary file from {request.remote_addr}: {str(e)}")
            return jsonify({'error': f'Error writing to temporary file: {str(e)}'}), 500

        finally:
            try:
                os.close(fd) # Ensure file descriptor is closed
                # Use shutil.rmtree for secure deletion (handles permissions better)
                #shutil.rmtree(os.path.dirname(temp_file_path), ignore_errors=True) # Delete the directory and its contents
                #os.remove(temp_file_path)  # Remove the temporary file
            except Exception as e:
                logging.error(f"Error cleaning up temporary file: {str(e)}")


    except Exception as e:
        logging.error(f"Error processing request from {request.remote_addr}: {str(e)}")
        return jsonify({'error': f'Error processing request: {str(e)}'}), 400


# Example endpoint to retrieve the file content using the hash (requires authentication)
@app.route('/get_file_content/<file_hash>', methods=['GET'])
#@login_required
def get_file_content(file_hash):
    """Retrieves the content of a file based on its hash."""
    db = SessionLocal()
    try:
        file_hash_obj = db.query(FileHash).filter(FileHash.file_hash == file_hash).first()
        if not file_hash_obj:
            return jsonify({'error': 'File not found'}), 404

        file_path = file_hash_obj.file_path
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({'content': content}), 200
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {str(e)}")
            return jsonify({'error': f'Error reading file: {str(e)}'}), 500
    finally:
        db.close()


# Background task for deleting old temporary files (example using APScheduler)
from apscheduler.schedulers.background import BackgroundScheduler

def cleanup_old_files():
    """Deletes temporary files older than a certain age."""
    logging.info("Running cleanup task...")
    db = SessionLocal()
    try:
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)  # Delete files older than 1 day
        old_files = db.query(FileHash).filter(FileHash.created_at < cutoff_date).all()

        for file_hash_obj in old_files:
            file_path = file_hash_obj.file_path
            try:
                os.remove(file_path)
                logging.info(f"Deleted old file: {file_path}")
            except Exception as e:
                logging.error(f"Error deleting file {file_path}: {str(e)}")

            db.delete(file_hash_obj)

        db.commit()
    except Exception as e:
        db.rollback()
        logging.error(f"Error during cleanup: {str(e)}")
    finally:
        db.close()
    logging.info("Cleanup task completed.")


scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_old_files, 'interval', days=1)  # Run cleanup daily
scheduler.start()


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

