import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("SELECT id, username, email, password_hash, salt, role, created_at FROM users")
rows = cursor.fetchall()

print("USERS TABLE:\n")
for row in rows:
    print(f"ID: {row[0]}")
    print(f"Username: {row[1]}")
    print(f"Email: {row[2]}")
    print(f"Password Hash: {row[3]}")
    print(f"Salt: {row[4]}")
    print(f"Role: {row[5]}")
    print(f"Created At: {row[6]}")
    print("-" * 40)

conn.close()
