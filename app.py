from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, send_file
)
import sqlite3
import hashlib
import os
import random
import io
import base64
from datetime import datetime, timedelta

# -------- CRYPTO IMPORTS --------
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# -------- APP SETUP --------
app = Flask(__name__)
app.secret_key = "briefcase_secret_key"
app.config["SESSION_PERMANENT"] = False

server_started = False

# -------- DATABASE --------
def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Reset sessions on server start (Flask 3 safe)
@app.before_request
def reset_sessions_on_startup():
    global server_started
    if not server_started:
        conn = get_db_connection()
        conn.execute("UPDATE users SET is_logged_in = 0")
        conn.commit()
        conn.close()
        server_started = True

@app.before_request
def enforce_session_validity():
    # Routes that do NOT require login
    public_routes = {"login", "register", "verify_otp", "home", "static"}

    if request.endpoint in public_routes:
        return

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Re-check login status from DB (no cached access)
    conn = get_db_connection()
    user = conn.execute(
        "SELECT is_logged_in FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    conn.close()

    if not user or user["is_logged_in"] == 0:
        session.clear()
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))


# -------- SECURITY HELPERS --------
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def generate_otp():
    return str(random.randint(100000, 999999))

# -------- ACL --------
ACL = {
    "admin": ["upload", "download", "delete"],
    "uploader": ["upload", "download"],
    "viewer": ["download"]
}

def is_allowed(role, action):
    return action in ACL.get(role, [])

# -------- RSA KEYS --------
def load_public_key():
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

# -------- HYBRID ENCRYPTION --------
def aes_encrypt(data):
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return key, iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def rsa_encrypt_key(aes_key):
    return load_public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_key(encrypted_key):
    return load_private_key().decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# -------- DIGITAL SIGNATURE --------
def sign_data(data):
    return load_private_key().sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data, signature):
    try:
        load_public_key().verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -------- FILE HELPERS --------
def get_all_files():
    conn = get_db_connection()
    files = conn.execute("SELECT id, filename FROM files").fetchall()
    conn.close()
    return files

# -------- ROUTES --------

@app.route("/")
def index():
    return render_template("index.html")

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        salt = os.urandom(16).hex()
        password_hash = hash_password(request.form["password"], salt)

        role = "viewer"  # 🔐 enforced default role

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO users (username, email, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            request.form["username"],
            request.form["email"],
            password_hash,
            salt,
            role,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()

        flash("Account created successfully. Please sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (request.form["username"],)
        ).fetchone()
        conn.close()

        if user:
            entered_hash = hash_password(request.form["password"], user["salt"])
            if entered_hash == user["password_hash"]:
                otp = generate_otp()
                expiry = (datetime.now() + timedelta(minutes=2)).isoformat()

                conn = get_db_connection()
                conn.execute(
                    "UPDATE users SET otp=?, otp_expiry=? WHERE id=?",
                    (otp, expiry, user["id"])
                )
                conn.commit()
                conn.close()

                session["temp_user_id"] = user["id"]
                print("OTP (demo):", otp)
                return redirect(url_for("verify_otp"))

        flash("Incorrect username or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")

# -------- OTP --------
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "temp_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        conn = get_db_connection()
        user = conn.execute(
            "SELECT otp, otp_expiry, role FROM users WHERE id=?",
            (session["temp_user_id"],)
        ).fetchone()

        if user and user["otp"] == request.form["otp"]:
            if datetime.now() <= datetime.fromisoformat(user["otp_expiry"]):
                conn.execute(
                    "UPDATE users SET otp=NULL, otp_expiry=NULL, is_logged_in=1 WHERE id=?",
                    (session["temp_user_id"],)
                )
                conn.commit()
                conn.close()

                session["user_id"] = session.pop("temp_user_id")
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))

        conn.close()
        flash("Invalid or expired OTP. Please try again.", "error")
        return redirect(url_for("verify_otp"))

    return render_template("verify_otp.html")

# -------- DASHBOARD --------
@app.route("/dashboard")
def dashboard():
    return render_template(
        "dashboard.html",
        role=session.get("role")
    )


# -------- UPLOAD (STAY ON PAGE) --------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    role = session.get("role")

    if not is_allowed(role, "upload"):
        return render_template("upload.html", can_upload=False)

    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            flash("Please select a file to upload.", "warning")
            return render_template("upload.html", can_upload=True)

        data = file.read()
        aes_key, iv, ciphertext = aes_encrypt(data)
        encoded_key = base64.b64encode(rsa_encrypt_key(aes_key))
        signature = sign_data(ciphertext)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO files (filename, owner_id, uploaded_at)
            VALUES (?, ?, ?)
        """, (file.filename, session["user_id"], datetime.now().isoformat()))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()

        with open(f"uploads/encrypted_files/{file_id}.bin", "wb") as f:
            f.write(ciphertext)
        with open(f"uploads/encrypted_keys/{file_id}.key", "wb") as f:
            f.write(encoded_key)
        with open(f"uploads/ivs/{file_id}.iv", "wb") as f:
            f.write(iv)
        with open(f"uploads/signatures/{file_id}.sig", "wb") as f:
            f.write(signature)

        flash("File uploaded securely and encrypted successfully.", "success")
        return render_template("upload.html", can_upload=True)

    return render_template("upload.html", can_upload=True)


# -------- DOWNLOAD (STAY ON PAGE) --------
@app.route("/download", methods=["GET", "POST"])
def download():
    role = session.get("role")
    files = get_all_files()

    if not is_allowed(role, "download"):
        flash("You do not have permission to download files.", "error")
        return render_template("download.html", files=files, role=role)

    if request.method == "POST":
        file_id = request.form["file_id"]

        with open(f"uploads/encrypted_files/{file_id}.bin", "rb") as f:
            ciphertext = f.read()
        with open(f"uploads/encrypted_keys/{file_id}.key", "rb") as f:
            encrypted_key = base64.b64decode(f.read())
        with open(f"uploads/ivs/{file_id}.iv", "rb") as f:
            iv = f.read()
        with open(f"uploads/signatures/{file_id}.sig", "rb") as f:
            signature = f.read()

        if not verify_signature(ciphertext, signature):
            flash(
                "File integrity verification failed. The file may have been tampered with.",
                "error"
            )
            return render_template("download.html", files=files, role=role)

        plaintext = aes_decrypt(rsa_decrypt_key(encrypted_key), iv, ciphertext)

        conn = get_db_connection()
        filename = conn.execute(
            "SELECT filename FROM files WHERE id = ?",
            (file_id,)
        ).fetchone()["filename"]
        conn.close()

        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=filename
        )

    return render_template("download.html", files=files, role=role)

# -------- DELETE --------
@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if not is_allowed(session.get("role"), "delete"):
        flash("You do not have permission to delete files.", "error")
        return render_template(
            "download.html",
            files=get_all_files(),
            role=session.get("role")
        )

    paths = [
        f"uploads/encrypted_files/{file_id}.bin",
        f"uploads/encrypted_keys/{file_id}.key",
        f"uploads/ivs/{file_id}.iv",
        f"uploads/signatures/{file_id}.sig"
    ]

    for path in paths:
        if os.path.exists(path):
            os.remove(path)

    conn = get_db_connection()
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()

    flash("File deleted successfully.", "success")
    return render_template(
        "download.html",
        files=get_all_files(),
        role=session.get("role")
    )


@app.route("/request-upload", methods=["POST"])
def request_upload():
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET upload_requested = 1 WHERE id = ?",
        (session["user_id"],)
    )
    conn.commit()
    conn.close()

    flash("Upload access request sent to administrator.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/requests")
def admin_requests():
    if session.get("role") != "admin":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    requests = conn.execute(
        "SELECT id, username FROM users WHERE upload_requested = 1"
    ).fetchall()
    conn.close()

    return render_template("admin_requests.html", requests=requests)


@app.route("/admin/approve/<int:user_id>", methods=["POST"])
def approve_upload(user_id):
    if session.get("role") != "admin":
        flash("Unauthorized action.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET role='uploader', upload_requested=0 WHERE id=?",
        (user_id,)
    )
    conn.commit()
    conn.close()

    flash("Upload access granted.", "success")
    return redirect(url_for("admin_requests"))


@app.route("/admin/decline/<int:user_id>", methods=["POST"])
def decline_upload(user_id):
    if session.get("role") != "admin":
        flash("Unauthorized action.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET upload_requested = 0 WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()

    flash("Upload request declined.", "warning")
    return redirect(url_for("admin_requests"))



# -------- LOGOUT --------
@app.route("/logout")
def logout():
    if "user_id" in session:
        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET is_logged_in=0 WHERE id=?",
            (session["user_id"],)
        )
        conn.commit()
        conn.close()

    session.clear()
    return redirect(url_for("login"))

# -------- RUN --------
if __name__ == "__main__":
    app.run(debug=True)