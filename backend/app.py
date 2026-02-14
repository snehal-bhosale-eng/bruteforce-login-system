from datetime import datetime
from flask import Flask, request, render_template_string
import sqlite3
import bcrypt
import os


app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "..", "database", "security_project.db")
print("DATABASE PATH:", DB_NAME)





# ---------------- DATABASE HELPERS ----------------
def get_db():
    return sqlite3.connect(DB_NAME)


def create_users_table():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def create_login_logs_table():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            success INTEGER,
            ip_address TEXT,
            user_agent TEXT
        )
    """)

    conn.commit()
    conn.close()
    


def add_user(username, password):
    conn = get_db()
    cursor = conn.cursor()

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # user already exists

    conn.close()

    


# ---------------- ROUTES ----------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")


    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    # Default: failed attempt
    success = 0

    if user and bcrypt.checkpw(password.encode(), user[0]):
        success = 1
       
    current_time = datetime.now()
    ip_address = request.remote_addr
    from datetime import timedelta

    # 🔹 Define time window (2 minutes)
    window_start = current_time - timedelta(minutes=2)

    # 🔹 Count attempts from same IP within last 2 minutes
    cursor.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE ip_address = ?
    AND timestamp >= ?
    """, (ip_address, window_start.isoformat()))

    result = cursor.fetchone()
    continuous_attempts = result[0] if result else 0

    print("Continuous Attempts:", continuous_attempts)
    suspicious_continuity = False

    if continuous_attempts >= 4:
     print("🚨 RETRY CONTINUITY DETECTED")



    user_agent = request.headers.get("User-Agent")

    # 🔹 Fetch previous attempt from same IP
    cursor.execute("""
        SELECT timestamp
        FROM login_logs
        WHERE ip_address = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (ip_address,))

    row = cursor.fetchone()

    if row:
        previous_time = datetime.fromisoformat(row[0])
        time_gap = (current_time - previous_time).total_seconds()
    else:
        time_gap = None

    print("Time Gap:", time_gap)


    # 🔥 INSERT INTO login_logs (THIS WAS MISSING)
    cursor.execute("""
        INSERT INTO login_logs (username, timestamp, success, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    """, (username, current_time.isoformat(), success, ip_address, user_agent))

    conn.commit()
    conn.close()


    if success == 1:
        return render_template_string(
            f"<h2>Login Successful</h2><p>Welcome, {username}</p>"
        )

    return render_template_string("<h2>Invalid username or password</h2>")



# ---------------- APP START ----------------

if __name__ == "__main__":
    create_users_table()
    create_login_logs_table()   # ADD THIS

    add_user("admin", "admin123")
    add_user("user", "password123")

    app.run(debug=True)


    # TEMP users (only added once)
    add_user("admin", "admin123")
    add_user("user", "password123")

    app.run(debug=True)
