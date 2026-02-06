import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Enable foreign key constraints
cursor.execute("PRAGMA foreign_keys = ON;")

# -----------------------------
# USERS TABLE
# -----------------------------
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,

    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,

    role TEXT NOT NULL CHECK (role IN ('viewer', 'uploader', 'admin')),

    is_logged_in INTEGER DEFAULT 0 CHECK (is_logged_in IN (0, 1)),

    otp TEXT,
    otp_expiry TEXT,

    upload_requested INTEGER DEFAULT 0 CHECK (upload_requested IN (0, 1)),

    created_at TEXT NOT NULL
)
""")


conn.commit()
conn.close()

print("Database initialized successfully.")
