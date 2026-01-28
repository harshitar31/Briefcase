import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    owner_id INTEGER,
    uploaded_at TEXT
)
""")

conn.commit()
conn.close()

print("Files table created.")
