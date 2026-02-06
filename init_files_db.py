# import sqlite3

# conn = sqlite3.connect("database.db")
# cursor = conn.cursor()

# # Enable foreign key constraints
# cursor.execute("PRAGMA foreign_keys = ON;")


# # -----------------------------
# # FILES TABLE
# # -----------------------------
# cursor.execute("""
# CREATE TABLE IF NOT EXISTS files (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,

#     filename TEXT NOT NULL,
#     owner_id INTEGER NOT NULL,
#     uploaded_at TEXT NOT NULL,

#     FOREIGN KEY (owner_id)
#         REFERENCES users(id)
#         ON DELETE CASCADE
# )
# """)

# conn.commit()
# conn.close()

# print("Database initialized successfully.")


import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Enable foreign key constraints
cursor.execute("PRAGMA foreign_keys = ON;")


# -----------------------------
# FILES TABLE
# -----------------------------
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    filename TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL,

    FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON DELETE CASCADE
)
""")

conn.commit()
conn.close()

print("Database initialized successfully.")
