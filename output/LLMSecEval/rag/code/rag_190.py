import configparser

   # Configuration
   CONFIG_FILE = 'config.ini'

   def load_config():
       config = configparser.ConfigParser()
       config.read(CONFIG_FILE)
       return config

   config = load_config()
   DATABASE = config['Database']['path']
   app.secret_key = config['Security']['secret_key']
   DEFAULT_ADMIN_USERNAME = config['Admin']['default_username']

   # ... rest of your code ...

