sql = "SELECT * FROM users WHERE username = %s"
   val = (username,)  # username is a variable containing user input
   cursor.execute(sql, val)

