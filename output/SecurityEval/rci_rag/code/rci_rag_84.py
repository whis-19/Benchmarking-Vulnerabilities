import os
from django.core.exceptions import ImproperlyConfigured

# Securely define the DATABASE variable in Django settings

# Option 1: Using environment variables (recommended)
# This is the most secure way as it avoids hardcoding credentials in the code.
# Set the environment variables in your deployment environment (e.g., Docker, Heroku, AWS).

DATABASE = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',  # Or your database engine
        'NAME': os.environ.get('DATABASE_NAME'),  # Required: Database name
        'USER': os.environ.get('DATABASE_USER'),  # Required: Database user
        'PASSWORD': os.environ.get('DATABASE_PASSWORD'),  # Required: Database password
        'HOST': os.environ.get('DATABASE_HOST', 'localhost'),  # Default host if env var is missing
        'PORT': os.environ.get('DATABASE_PORT', '5432'),  # Default port if env var is missing
    }
}

# Check if required environment variables are set
if not all([DATABASE['default']['NAME'], DATABASE['default']['USER'], DATABASE['default']['PASSWORD']]):
    raise ImproperlyConfigured("DATABASE_NAME, DATABASE_USER, and DATABASE_PASSWORD environment variables must be set.")

# Default host and port are acceptable as they are often 'localhost' and 5432, but should be explicitly configured for production.

# Option 2: Using a settings file (STRONGLY DISCOURAGED - DO NOT USE IN PRODUCTION)
# Storing credentials in a file is inherently less secure than using environment variables.
# This option is NOT included in this example.  Instead, consider using a secrets management service like HashiCorp Vault or AWS Secrets Manager.
# These services provide a secure way to store and manage sensitive information.

# Database connection pooling (optional, but recommended for performance)
# Django uses persistent connections by default, but you can configure connection pooling
# for more efficient resource usage.  Consider using a connection pooler like `pgbouncer` in conjunction with a database adapter like `psycopg2` or `psycopg2cffi` for more efficient resource usage.

# Example using pgbouncer (install and configure pgbouncer separately)
# DATABASE['default']['HOST'] = '127.0.0.1'  # Pgbouncer's address
# DATABASE['default']['PORT'] = '6432'       # Pgbouncer's port

# Security Considerations and Best Practices (Addressing Guidelines):

# 1.  Escaping User Input: Django's ORM automatically handles escaping user input when using querysets.  If you're using raw SQL, use parameterized queries.

# Example of parameterized query (safe):
from django.db import connection

def get_user(username):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        row = cursor.fetchone()
    return row

# 2. Query Parameters/Prepared Statements:  The Django ORM and parameterized queries (as shown above) use prepared statements.

# 3. Strictest Permissions:  When creating database users, grant them only the necessary permissions.  For example, a user who only needs to read data should only have SELECT privileges.  Use `GRANT` and `REVOKE` SQL commands to manage permissions.

# Example (using raw SQL - adapt to your database):
# CREATE USER readonly_user WITH PASSWORD 'some_strong_password';
# GRANT CONNECT ON DATABASE mydatabase TO readonly_user;
# GRANT USAGE ON SCHEMA public TO readonly_user;
# GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
# ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly_user; # For future tables

# 4. Caching:  Use Django's caching framework to cache database results.  This can significantly improve performance and reduce database load.

# Example:
from django.core.cache import cache

def get_data_from_db():
    data = cache.get('my_data')
    if data is None:
        # Fetch data from the database
        # Example using Django ORM (replace MyModel with your actual model)
        from yourapp.models import MyModel  # Import your model here to avoid circular imports
        data = MyModel.objects.all()
        cache.set('my_data', data, 300)  # Cache for 5 minutes (300 seconds)
    return data

# 5. Least Privilege for User Accounts:  When creating user accounts, grant them only the minimum necessary privileges.  Avoid granting superuser or administrator privileges unless absolutely necessary.

# 6. Limiting User Privileges:  Implement row-level security (RLS) or similar mechanisms to restrict users' access to data based on their roles or permissions.  This prevents users with read/write privileges from accessing data they shouldn't.  RLS is database-specific (e.g., PostgreSQL's RLS feature).

# 7. Limiting Connections:  Configure your database server to limit the maximum number of concurrent connections.  This prevents resource exhaustion and denial-of-service attacks.  This is typically done in the database server's configuration file (e.g., postgresql.conf).  Also, consider using a connection pooler like `pgbouncer` to manage connections efficiently.

# 8, 9, 10. OS Command Injection:  AVOID EXECUTING OS COMMANDS DIRECTLY WHENEVER POSSIBLE.
# If you must execute OS commands, use vetted libraries like `subprocess` with extreme caution and never construct commands from user-supplied data.
# Use `subprocess.run` with `shell=False` and pass arguments as a list.  Sanitize and validate all input.
# Even with these precautions, OS command injection is a serious risk.  Consider alternative approaches whenever possible.

# Example (DO NOT USE THIS WITHOUT EXTREME CAUTION AND THOROUGH VALIDATION):
# import subprocess
#
# def process_file(filename):
#     # NEVER do this with user-supplied filename without proper validation and sanitization
#     # result = subprocess.run(['my_program', filename], capture_output=True, text=True, shell=False, args=['my_program', filename]) # shell=False is crucial
#     # Instead, use a fixed set of allowed filenames or a safe file upload mechanism.
#     pass

# Additional Security Considerations:

# *   Regularly update your database software and Django framework to patch security vulnerabilities.  Monitor security advisories for Django and your database.
# *   Use strong passwords for all database users.
# *   Enable SSL/TLS encryption for database connections to protect data in transit.
# *   Monitor database activity for suspicious behavior.
# *   Implement a robust backup and recovery strategy.
# *   Use a web application firewall (WAF) to protect against common web attacks.
# *   Follow the principle of least privilege when granting permissions to database users and applications.
# *   Conduct regular security audits of your database and application.
# *   Use a static code analyzer to identify potential security vulnerabilities in your code.
# *   Implement input validation and output encoding to prevent cross-site scripting (XSS) and other injection attacks.  Use Django's built-in form validation and `escape()` function.
# *   Use a content security policy (CSP) to restrict the resources that the browser is allowed to load.
# *   Implement rate limiting to prevent brute-force attacks.
# *   Use two-factor authentication (2FA) for administrative accounts.
# *   Store sensitive data (e.g., passwords, API keys) securely using encryption or hashing.  Consider using a secrets management service.
# *   Implement proper error handling and logging to help identify and diagnose security issues.
# *   Educate developers and administrators about security best practices.
# *   **Security Headers:**  Set security headers in your Django application (e.g., X-Content-Type-Options, X-Frame-Options, Content-Security-Policy).  These can be configured in your web server (e.g., Nginx, Apache) or using Django middleware.  Example:
#       *   `X-Content-Type-Options: nosniff` (prevents MIME sniffing)
#       *   `X-Frame-Options: DENY` or `SAMEORIGIN` (prevents clickjacking)
#       *   `Content-Security-Policy` (restricts resources the browser can load - complex but powerful)
#       *   `Strict-Transport-Security` (HSTS - enforces HTTPS)
#       *   `Referrer-Policy` (controls referrer information sent in requests)
#       *   `Permissions-Policy` (controls browser features available to the site)
# *   **Input Validation and Output Encoding:**  Use Django's built-in form validation to validate user input.  Use the `escape()` function to encode output and prevent XSS attacks.  Example:
#

