import sqlite3

    conn = sqlite3.connect('temperature_data.db')
    cursor = conn.cursor()

    cursor.execute("INSERT INTO temperature_data (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)",
                   (34.0522, -118.2437, '2023-10-27', 25.0))

    conn.commit()
    conn.close()

