from sqlalchemy import create_engine, text

    engine = create_engine('postgresql://user:password@host:port/database')
    with engine.connect() as conn:
        username = 'user123'
        result = conn.execute(text("SELECT * FROM users WHERE username = :username"), {"username": username})
        for row in result:
            print(row)

