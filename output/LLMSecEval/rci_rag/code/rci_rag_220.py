import os
import re
import shutil
import uuid
from flask import Flask, request, abort, make_response
from werkzeug.utils import secure_filename
import magic  # For more accurate MIME type detection
import hashlib  # For file hashing
from datetime import datetime # For logging

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = '/var/www/uploads'  #  Important:  Use an absolute path
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
CHROOT_PATH = '/var/www/chroot' # Path for chroot jail (USE WITH EXTREME CAUTION)
LOG_FILE = '/var/log/upload_security.log' # Log file for security events

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Ensure chroot path exists (if using)
os.makedirs(CHROOT_PATH, exist_ok=True)

# Ensure log file exists
with open(LOG_FILE, 'a'):  # Create if it doesn't exist
    pass

def log_security_event(message):
    """Logs security-related events to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def has_single_extension(filename):
    """
    Checks if the filename has only one extension.  Prevents double-extension attacks.
    """
    return filename.count('.') == 1

def validate_file_content(file_path):
    """
    Validates the file content using python-magic.
    """
    try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_path)

        if mime_type.startswith('image/'):
            # Further image validation (e.g., check for specific image formats)
            # using libraries like Pillow
            # Example: Check image dimensions, pixel depth, etc.
            pass
        elif mime_type == 'text/plain':
            # Further text file validation (e.g., check for embedded scripts)
            # Example: Check for embedded HTML tags or JavaScript
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: # Handle encoding issues
                content = f.read()
                if "<script" in content.lower() or "<html" in content.lower():
                    log_security_event(f"Potential XSS in text file: {file_path}")
                    return False
        elif mime_type == 'application/pdf':
            # Further PDF validation (e.g., check for embedded JavaScript)
            # Consider using a dedicated PDF parsing library for more robust checks
            pass
        else:
            log_security_event(f"Disallowed MIME type: {mime_type} for file: {file_path}")
            print(f"Disallowed MIME type: {mime_type}")
            return False  # Unknown or disallowed MIME type

        return True
    except Exception as e:
        log_security_event(f"Content validation error: {e} for file: {file_path}")
        print(f"Content validation error: {e}")
        return False

def validate_filename_redos(filename, timeout=0.1):
    """
    Validates the filename against a ReDoS-vulnerable regex with a timeout.
    """
    # Example vulnerable regex (DO NOT USE THIS IN PRODUCTION without timeout!)
    redos_pattern = r"^(a+)+$"
    try:
        match = re.match(redos_pattern, filename, timeout=timeout)
        return bool(match)  # Returns True if match is found (vulnerable)
    except TimeoutError:
        log_security_event(f"ReDoS attack suspected in filename: {filename}")
        print("ReDoS attack suspected in filename!")
        return False  # ReDoS attack suspected
    except Exception as e:
        log_security_event(f"Regex validation error: {e} for filename: {filename} - {e}")
        print(f"Regex validation error: {e}")
        return False

def calculate_file_hash(file_path):
    """Calculates the SHA256 hash of the file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads securely.
    """
    if 'file' not in request.files:
        log_security_event("No file part in request")
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        log_security_event("No selected file")
        return "No selected file", 400

    if file:
        filename = secure_filename(file.filename)

        # Prevent ReDoS attacks on filename
        if not validate_filename_redos(filename):
            log_security_event(f"Invalid filename (potential ReDoS attack): {filename}")
            return "Invalid filename (potential ReDoS attack)", 400

        if not allowed_file(filename):
            log_security_event(f"File type not allowed: {filename}")
            return "File type not allowed", 400

        if not has_single_extension(filename):
            log_security_event(f"Filename must have a single extension: {filename}")
            return "Filename must have a single extension", 400

        # Generate a unique filename to prevent overwrites and information disclosure
        unique_filename = str(uuid.uuid4()) + "_" + filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            # Save the file
            file.save(filepath)

            # Validate file content using python-magic
            if not validate_file_content(filepath):
                log_security_event(f"Invalid file content for file: {filepath}")
                os.remove(filepath)  # Remove invalid file
                return "Invalid file content", 400

            # Calculate file hash for integrity checks and deduplication
            file_hash = calculate_file_hash(filepath)
            log_security_event(f"File uploaded successfully: {filepath} - SHA256: {file_hash}")

            # Optional: Chroot jail (USE WITH EXTREME CAUTION - see warnings below)
            # chroot_upload(filepath)

            # Return success message
            return "File uploaded successfully", 200

        except Exception as e:
            log_security_event(f"Error during file processing: {e} for file: {filepath}")
            print(f"Error during file processing: {e}")
            return "Error uploading file", 500

    log_security_event("Upload failed - unknown reason")
    return "Upload failed", 400

@app.after_request
def add_csp_header(response):
    """
    Adds a Content Security Policy (CSP) header to mitigate XSS attacks.
    """
    #  Consider a more restrictive CSP in production
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; style-src 'self' 'unsafe-inline'"
    return response

def chroot_upload(filepath):
    """
    Attempts to chroot the uploaded file into a restricted environment.

    WARNING: Chroot is NOT a robust security measure. It can be bypassed.
    Consider using Docker or VMs for stronger sandboxing.
    """
    try:
        # Create the destination directory within the chroot
        dest_dir = os.path.join(CHROOT_PATH, os.path.dirname(filepath.replace(app.config['UPLOAD_FOLDER'], '').lstrip('/')))
        os.makedirs(dest_dir, exist_ok=True)

        # Copy the file to the chroot environment, preserving metadata
        dest_path = os.path.join(dest_dir, os.path.basename(filepath))
        shutil.copy2(filepath, dest_path)

        # Change the root directory to the chroot path
        os.chroot(CHROOT_PATH)

        # The file is now accessible within the chroot at dest_path (relative to CHROOT_PATH)
        print(f"File chrooted to: {dest_path}")

        # Clean up the original file (optional, but recommended)
        os.remove(filepath)

    except OSError as e:
        log_security_event(f"Chroot failed: {e} for file: {filepath}")
        print(f"Chroot failed: {e}")
        # Handle the error appropriately (e.g., log the error, return an error message)
    finally:
        # Ensure the current working directory is reset after chroot
        os.chdir('/')


# Additional Security Considerations (Beyond the Code):

# 1. Regular Security Audits: Conduct regular security audits of your code and infrastructure.
# 2. Dependency Management: Keep your dependencies up-to-date to patch vulnerabilities. Use tools like pip-audit or Dependabot.
# 3. Web Application Firewall (WAF): Implement a WAF to protect against common web attacks.
# 4. Input Validation:  Thoroughly validate all user inputs, not just the filename.
# 5. Output Encoding: Encode all output to prevent XSS attacks.
# 6. Rate Limiting: Implement rate limiting to prevent DoS attacks.
# 7. Logging and Monitoring: Implement comprehensive logging and monitoring to detect and respond to security incidents.
# 8. Principle of Least Privilege: Run your application with the least privileges necessary.
# 9. Secure Configuration:  Store sensitive configuration data (e.g., API keys, database passwords) securely, using environment variables or a secrets management system.
# 10. Error Handling:  Implement robust error handling to prevent information leakage.  Avoid displaying sensitive information in error messages.
# 11. HTTPS:  Always use HTTPS to encrypt communication between the client and the server.
# 12. Content Security Policy (CSP):  Use CSP to control the resources that the browser is allowed to load, mitigating XSS attacks. (Example provided above)
# 13. Subresource Integrity (SRI):  Use SRI to ensure that third-party resources have not been tampered with.
# 14. Clickjacking Protection:  Set the X-Frame-Options header to prevent clickjacking attacks.
# 15. Cross-Site Request Forgery (CSRF) Protection:  Implement CSRF protection to prevent attackers from forging requests on behalf of legitimate users.
# 16. Denial-of-Service (DoS) Protection: Implement measures to protect against DoS attacks, such as rate limiting and request filtering.
# 17. Regular Expression Denial of Service (ReDoS) Protection:  Be careful when using regular expressions, as they can be vulnerable to ReDoS attacks.  Use timeouts or alternative regex engines. (Example provided above)
# 18. Filesystem Permissions:  Set appropriate filesystem permissions to restrict access to uploaded files.
# 19. Data Encryption:  Consider encrypting sensitive data at rest.
# 20. User Authentication and Authorization:  Implement strong user authentication and authorization mechanisms to control access to resources.
# 21. File Hashing: Calculate and store file hashes (e.g., SHA256) to detect file modifications or duplicates.
# 22. Centralized Logging: Implement centralized logging to aggregate logs from multiple sources for easier analysis and incident response.
# 23. Security Information and Event Management (SIEM): Consider using a SIEM system to correlate security events and identify potential threats.
# 24. Input Sanitization: Sanitize user inputs to prevent injection attacks.
# 25. Output Escaping: Escape user-generated content before displaying it to prevent XSS attacks.

if __name__ == '__main__':
    app.run(debug=True)

