# import sqlite3

# conn = sqlite3.connect("database.db")
# cursor = conn.cursor()

# cursor.execute("""
# ALTER TABLE users ADD COLUMN is_logged_in INTEGER DEFAULT 0
# """)

# conn.commit()
# conn.close()

# print("Database updated.")


import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
ALTER TABLE users ADD COLUMN otp TEXT
""")

cursor.execute("""
ALTER TABLE users ADD COLUMN otp_expiry TEXT
""")

conn.commit()
conn.close()

print("OTP columns added.")
