
from datetime import datetime, timedelta
from ipaddress import ip_address
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
def create_blocked_ips_table():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address TEXT PRIMARY KEY,
            blocked_until TEXT
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

# ---------------- RISK ENGINE HELPERS ----------------

def is_ip_blocked(ip):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT blocked_until FROM blocked_ips
        WHERE ip_address = ?
    """, (ip,))

    row = cursor.fetchone()
    conn.close()

    if row:
        blocked_until = datetime.fromisoformat(row[0])
        if datetime.now() < blocked_until:
            return True

    return False


def block_ip(ip, minutes=10):
    conn = get_db()
    cursor = conn.cursor()

    blocked_until = datetime.now() + timedelta(minutes=minutes)

    cursor.execute("""
        INSERT OR REPLACE INTO blocked_ips (ip_address, blocked_until)
        VALUES (?, ?)
    """, (ip, blocked_until.isoformat()))

    conn.commit()
    conn.close()


def calculate_risk_score(time_gap, continuous_attempts, unique_usernames, fail_count):
    risk_score = 0

    if time_gap and time_gap < 2:
        risk_score += 20

    if continuous_attempts >= 4:
        risk_score += 30

    if unique_usernames >= 3:
        risk_score += 25

    if fail_count >= 5:
        risk_score += 25

    return risk_score


def get_risk_level(score):
    if score <= 30:
        return "Normal"
    elif score <= 60:
        return "Suspicious"
    else:
        return "Attack"

    


# ---------------- ROUTES ----------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip_address = request.remote_addr
    
    # Check if IP already blocked
    if is_ip_blocked(ip_address):
        return render_template_string(
            "<h2>Your IP is temporarily blocked due to suspicious activity.</h2>"
        )
    
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

    # =============================
    # FEATURE 3: Username Enumeration Detection
    # =============================
    cursor.execute("""
        SELECT username
        FROM login_logs
        WHERE ip_address = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (ip_address,))

    rows = cursor.fetchall()
    usernames = [row[0] for row in rows]
    usernames.append(username)
    unique_usernames = len(set(usernames))

    print("Unique Usernames (Last 5):", unique_usernames)
    if unique_usernames >= 3:
        print("🚨 USERNAME ENUMERATION DETECTED")

    # =============================
    # FEATURE 4: Failed Attempts Persistence
    # =============================
    fail_window = current_time - timedelta(minutes=5)
    cursor.execute("""
        SELECT COUNT(*)
        FROM login_logs
        WHERE ip_address = ?
        AND success = 0
        AND timestamp >= ?
    """, (ip_address, fail_window.isoformat()))

    fail_count = cursor.fetchone()[0]
    print("Failed Attempts:", fail_count)

    # =============================
    # FEATURE 2: Retry Continuity Detection
    # =============================
    window_start = current_time - timedelta(minutes=2)
    cursor.execute("""
        SELECT COUNT(*)
        FROM login_logs
        WHERE ip_address = ?
        AND timestamp >= ?
    """, (ip_address, window_start.isoformat()))

    result = cursor.fetchone()
    continuous_attempts = result[0] if result else 0

    print("Continuous Attempts:", continuous_attempts)
    if continuous_attempts >= 4:
        print("🚨 RETRY CONTINUITY DETECTED")

    # =============================
    # FEATURE 1: Time Gap Detection
    # =============================
    cursor.execute("""
        SELECT timestamp
        FROM login_logs
        WHERE ip_address = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (ip_address,))
    # =====================================================
# RISK ENGINE
# =====================================================
    risk_score = calculate_risk_score(
    time_gap,
    continuous_attempts,
    unique_usernames,
    fail_count
   ) 

    risk_level = get_risk_level(risk_score)

    print("Risk Score:", risk_score)
    print("Risk Level:", risk_level)

    if risk_level == "Attack":
        block_ip(ip_address)
        return render_template_string(
        "<h2>🚨 Suspicious activity detected. Your IP is temporarily blocked.</h2>"
    )

    row = cursor.fetchone()

    if row:
        previous_time = datetime.fromisoformat(row[0])
        time_gap = (current_time - previous_time).total_seconds()
    else:
        time_gap = None

    print("Time Gap:", time_gap)

    # Insert login attempt into logs
    cursor.execute("""
        INSERT INTO login_logs (username, timestamp, success, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    """, (username, current_time.isoformat(), success, ip_address, user_agent))

    conn.commit()
    conn.close()




# ---------------- APP START ----------------

if __name__ == "__main__":
    create_users_table()
    create_login_logs_table()
    create_blocked_ips_table()

    add_user("admin", "admin123")
    add_user("user", "password123")

    app.run(debug=True)
