import os
from flask import Flask
import secrets  # Import the secrets module

app = Flask(__name__)

# Ensure the FLASK_SECRET_KEY environment variable is set.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set for production.")
    # Or consider a more specific exception:
    # raise RuntimeError("FLASK_SECRET_KEY environment variable must be set for production.")

# IMPORTANT:  Generate this key *ONCE* and store it securely.  Do *NOT*
# generate a new key every time the application starts.  See documentation
# for secure key storage options.
# python -c "import secrets; print(secrets.token_hex(32))"
# Then set the FLASK_SECRET_KEY environment variable to the output.
# The secrets.token_hex() function is preferred over directly using os.urandom()
# because it returns a hexadecimal string representation of the random bytes,
# which is easier to handle and store as an environment variable.

# In a development environment, you can temporarily set the `FLASK_SECRET_KEY`
# environment variable to a simple string for testing purposes. However,
# *never* use this approach in production.

# Further security considerations:
# 1. Use a production-ready web server (e.g., Gunicorn, uWSGI).
# 2. Enable HTTPS.
# 3. Consider key rotation.
# 4. Conduct regular security audits.
# 5. For larger deployments, consider using a secrets management system like
#    HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Google Cloud
#    Secret Manager. These systems provide centralized storage, access control,
#    auditing, and rotation of secrets, making it easier to manage sensitive
#    data across your infrastructure.

