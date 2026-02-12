import os
import configparser

config = configparser.ConfigParser()
config_file = 'config.ini'
config.read(config_file)

# Database Configuration
db_file = os.environ.get('DB_FILE', config.get('database', 'db_file', fallback='users.db'))
db_user = os.environ.get('DB_USER', config.get('database', 'db_user', fallback='default_user'))
db_password = os.environ.get('DB_PASSWORD', config.get('database', 'db_password', fallback='default_password'))

print(f"Using database file: {db_file}")
print(f"Using database user: {db_user}")
# Don't print the password in a real application!
# print(f"Using database password: {db_password}")

