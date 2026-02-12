import logging
import os

# Configure logging based on environment
if os.environ.get("ENVIRONMENT") == "production":
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.DEBUG)

# Best practices for environment variables:
# - Don't hardcode them in your code.
# - Use a .env file for development (but never commit it).
# - In production, use a secure way to store and manage them (e.g., AWS Secrets Manager).

