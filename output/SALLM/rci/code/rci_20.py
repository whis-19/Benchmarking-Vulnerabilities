app.config['SQLALCHEMY_POOL_SIZE'] = 5  # Number of connections to keep in the pool
  app.config['SQLALCHEMY_MAX_OVERFLOW'] = 10  # Maximum number of connections beyond the pool size
  app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600  # Recycle connections after 1 hour (in seconds)

