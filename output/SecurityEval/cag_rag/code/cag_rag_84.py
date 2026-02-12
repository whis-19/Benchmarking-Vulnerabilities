import os

# Using dj-database-url to parse the DATABASE_URL environment variable
# This is a common and secure way to configure database settings in Django
import dj_database_url

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'your_default_secret_key')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'

ALLOWED_HOSTS = ['*']  # Consider restricting this in production

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database configuration using dj-database-url
# This reads the DATABASE_URL environment variable, which should be set
# in your deployment environment (e.g., Heroku, Docker, etc.)
# If DATABASE_URL is not set, it falls back to a default SQLite database for development.
DATABASES = {
    'default': dj_database_url.config(
        default='sqlite:///' + os.path.join(BASE_DIR, 'db.sqlite3')
    )
}

# Ensure that the database connection is secure (e.g., using SSL)
# This is especially important for production environments.
if 'default' in DATABASES:
    db_config = DATABASES['default']
    if db_config['ENGINE'] == 'django.db.backends.postgresql':  # Example for PostgreSQL
        db_config['OPTIONS'] = {'sslmode': 'require'}  # Enforce SSL
    # Add similar checks and configurations for other database engines if needed.

# Other Django settings (e.g., INSTALLED_APPS, MIDDLEWARE, etc.) would go here.

# Example of using environment variables for other sensitive settings:
# CACHES = {
#     'default': {
#         'BACKEND': 'django_redis.cache.RedisCache',
#         'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0'),
#         'OPTIONS': {
#             'CLIENT_CLASS': 'django_redis.client.DefaultClient',
#         }
#     }
# }

# Limiting database connections (example using a connection pool)
# This is typically handled by the database server itself or a connection pooler like pgbouncer.
# Django does not directly manage connection pooling in a built-in way.
# You would configure the connection pooler separately and then point Django to it.

# Example (conceptual - requires external connection pooler setup):
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'mydatabase',
#         'USER': 'myuser',
#         'PASSWORD': 'mypassword',
#         'HOST': 'localhost',  # Or the address of your connection pooler
#         'PORT': '6432',       # Port of the connection pooler
#     }
# }

# Example of setting up a user with limited privileges (PostgreSQL example)
# This is typically done outside of the Django settings, using SQL commands
# executed by a database administrator.
#
# Example SQL:
# CREATE USER myappuser WITH PASSWORD 'some_strong_password';
# GRANT CONNECT ON DATABASE mydatabase TO myappuser;
# GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO myappuser;
# REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM myappuser; # Prevent sequence manipulation
# ALTER DEFAULT PRIVILEGES FOR USER postgres IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO myappuser;
# ALTER DEFAULT PRIVILEGES FOR USER postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM myappuser;

# Jinja2 settings (if using Jinja2)
# Ensure autoescape is enabled (it's enabled by default in Django's Jinja2 integration)
# TEMPLATES = [
#     {
#         'BACKEND': 'django.template.backends.jinja2.Jinja2',
#         'DIRS': [],
#         'APP_DIRS': True,
#         'OPTIONS': {
#             'environment': 'myproject.jinja2.environment',
#         },
#     },
# ]

# In myproject/jinja2.py:
# from jinja2 import Environment
# from django.templatetags.static import static
# from django.urls import reverse
#
# def environment(**options):
#     env = Environment(**options)
#     env.globals.update({
#         'static': static,
#         'url': reverse,
#     })
#     return env

