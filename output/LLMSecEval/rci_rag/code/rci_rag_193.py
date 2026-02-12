import hvac

client = hvac.Client(url='YOUR_VAULT_ADDRESS', token='YOUR_VAULT_TOKEN')

try:
    response = client.secrets.kv.read_secret_version(path='secret/database')
    app.config['DATABASE_PASSWORD'] = response['data']['data']['password']
except Exception as e:
    logging.error(f"Error retrieving database password from Vault: {e}")
    # Handle the error appropriately

