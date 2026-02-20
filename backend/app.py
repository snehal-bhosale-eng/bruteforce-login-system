from datetime import datetime, timedelta

from flask import Flask, request, render_template
import sqlite3
import bcrypt
import os


app = Flask(
    __name__,
    template_folder="../frontend",
    static_folder="../frontend"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "..", "database", "security_project.db")
print("DATABASE PATH:", DB_NAME)

# =====================================================
# DATABASE HELPERS
# =====================================================

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
            timestamp TEXT,
            success INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            risk_score INTEGER,
            risk_level TEXT
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
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

# =====================================================
# RISK ENGINE
# =====================================================

def is_ip_blocked(ip):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT blocked_until FROM blocked_ips WHERE ip_address = ?", (ip,))
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
    cursor.execute("INSERT OR REPLACE INTO blocked_ips (ip_address, blocked_until) VALUES (?, ?)",
                   (ip, blocked_until.isoformat()))
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

# =====================================================
# LOGIN ROUTE
# =====================================================

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    if is_ip_blocked(ip_address):
        return "<h2>Your IP is temporarily blocked.</h2>"

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    success = 0
    if user and bcrypt.checkpw(password.encode(), user[0]):
        success = 1

    current_time = datetime.now()

    # Feature 1 - Time Gap
    cursor.execute("SELECT timestamp FROM login_logs WHERE ip_address = ? ORDER BY timestamp DESC LIMIT 1", (ip_address,))
    row = cursor.fetchone()
    time_gap = (current_time - datetime.fromisoformat(row[0])).total_seconds() if row else None

    # Feature 2 - Retry Continuity
    window_start = current_time - timedelta(minutes=2)
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE ip_address = ? AND timestamp >= ?",
                   (ip_address, window_start.isoformat()))
    continuous_attempts = cursor.fetchone()[0]

    # Feature 3 - Username Enumeration
    cursor.execute("SELECT username FROM login_logs WHERE ip_address = ? ORDER BY timestamp DESC LIMIT 5",
                   (ip_address,))
    rows = cursor.fetchall()
    usernames = [r[0] for r in rows]
    usernames.append(username)
    unique_usernames = len(set(usernames))

    # Feature 4 - Failed Persistence
    fail_window = current_time - timedelta(minutes=5)
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE ip_address = ? AND success = 0 AND timestamp >= ?",
                   (ip_address, fail_window.isoformat()))
    fail_count = cursor.fetchone()[0]

    risk_score = calculate_risk_score(time_gap, continuous_attempts, unique_usernames, fail_count)
    risk_level = get_risk_level(risk_score)

    if risk_level == "Attack":
        block_ip(ip_address)
        conn.close()
        return "<h2>🚨 Suspicious activity detected. IP blocked.</h2>"

    cursor.execute("""
        INSERT INTO login_logs (username, timestamp, success, ip_address, user_agent, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, current_time.isoformat(), success, ip_address, user_agent, risk_score, risk_level))

    conn.commit()
    conn.close()

    if success:
        
        return f"<h2>Login Successful</h2><p>Welcome, {username}</p>"
    return "<h2>Invalid username or password</h2>"

# =====================================================
# DASHBOARD
# =====================================================
@app.route("/admin/security_dashboard")
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()

    # Total login attempts
    cursor.execute("SELECT COUNT(*) FROM login_logs")
    total_attempts = cursor.fetchone()[0]

    # Failed attempts
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE success = 0")
    failed_attempts = cursor.fetchone()[0]

    # Attack attempts
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk_level='Attack'")
    attack_attempts = cursor.fetchone()[0]

    # Suspicious attempts
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk_level='Suspicious'")
    suspicious_attempts = cursor.fetchone()[0]

    # Suspicious IP count
    cursor.execute("""
        SELECT COUNT(DISTINCT ip_address)
        FROM login_logs
        WHERE risk_level='Attack' OR risk_level='Suspicious'
    """)
    suspicious_ip_count = cursor.fetchone()[0]

    # Risk distribution
    cursor.execute("""
        SELECT risk_level, COUNT(*)
        FROM login_logs
        GROUP BY risk_level
    """)
    risk_distribution = cursor.fetchall()
    risk_labels = [row[0] for row in risk_distribution]
    risk_values = [row[1] for row in risk_distribution]

    # Recent logs
    cursor.execute("""
        SELECT username, timestamp, risk_score, risk_level
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    logs = cursor.fetchall()
    

    conn.close()
    return render_template(
    "dashboard.html",
    total_attempts=total_attempts,
    failed_attempts=failed_attempts,
    attack_attempts=attack_attempts,
    suspicious_attempts=suspicious_attempts,
    suspicious_ip_count=suspicious_ip_count,
    logs=logs,
    risk_labels=risk_labels,
    risk_values=risk_values
)
    
# =====================================================
# APP START
# =====================================================

if __name__ == "__main__":
    create_users_table()
    create_login_logs_table()
    create_blocked_ips_table()
    add_user("admin", "admin123")
    add_user("user", "password123")
    app.run(debug=True)