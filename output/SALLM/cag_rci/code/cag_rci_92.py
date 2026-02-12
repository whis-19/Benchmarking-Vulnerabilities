# Secure Secret Key Handling
import os
import secrets
import json  # For reading/writing JSON config

CONFIG_FILE = "config.json"

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

config = load_config()

if "secret_key" not in config:
    config["secret_key"] = secrets.token_hex(32)
    save_config(config)

SECRET_KEY = config["secret_key"]
app.config['SECRET_KEY'] = SECRET_KEY

# IMPORTANT:  The config.json file MUST be protected with appropriate file system permissions.
# Consider using more robust secret management solutions for production:
# - Environment variables (managed securely)
# - Secrets management systems (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
# - Encrypted configuration files

