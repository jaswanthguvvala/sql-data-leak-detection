"""
database.py - Database Layer for SQL-Based Data Leak Detection & Prevention System
==================================================================================
This module manages the SQLite database (security.db).
It handles:
1. Automatic database and table creation on application startup.
2. Initializing sample users with securely hashed passwords (PBKDF2/SHA256).
3. Inserting and retrieving security audit logs using parameterized queries.

NOTE FOR STUDENTS & TEACHERS:
- All queries strictly use parameterized queries (e.g., 'WHERE username = ?')
  to guarantee immunity from SQL Injection at the database execution layer.
- Passwords are NEVER stored in plain text.
- User passwords are NEVER recorded in the security logs.
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Path to the database file inside the 'database' folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, 'database')
DB_PATH = os.path.join(DB_DIR, 'security.db')


def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.
    Row factory is set to sqlite3.Row so columns can be accessed by name.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes the SQLite database tables and seeds sample accounts.
    Creates:
    - users: Stores registered accounts with role and password hash.
    - security_logs: Stores every security audit event (Login, SQLi, DLP).
    """
    # Ensure the 'database' directory exists
    os.makedirs(DB_DIR, exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Create the users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # 2. Create the security_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            input_text TEXT,
            detection_type TEXT,
            risk_level TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 3. Seed sample accounts if the users table is empty
    sample_users = [
        ('harsha', 'harsha123', 'Harsha', 'Student'),
        ('admin', 'admin123', 'Administrator', 'Admin'),
        ('student', 'student123', 'Student User', 'Student')
    ]

    for username, plain_password, name, role in sample_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if not existing_user:
            # Hash the password securely using PBKDF2/SHA256
            hashed_pwd = generate_password_hash(plain_password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
                (username, hashed_pwd, name, role)
            )

    conn.commit()
    conn.close()
    print("[Database] Database initialized and sample accounts verified.")


def get_user_by_username(username):
    """
    Retrieves a user record by username using a safe parameterized query.
    Case-insensitive lookup. Returns sqlite3.Row object or None.
    """
    if not username:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
    user = cursor.fetchone()
    conn.close()
    return user


def verify_user_credentials(username, password):
    """
    Verifies user credentials.
    1. Looks up the user using safe parameterized query.
    2. Compares plain password with the stored hash using check_password_hash.
    Returns (True, user_dict) on success, or (False, None) on failure.
    """
    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        return True, dict(user)
    return False, None


def user_exists(username):
    """
    Checks whether a user with the given username exists in the database.
    Uses parameterized query to prevent SQL injection.
    """
    if not username:
        return False
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def register_user(username, password, name=None, role='Student'):
    """
    Registers a new user account with PBKDF2/SHA256 password hash.
    Returns (True, user_dict) on success, or (False, error_message) on failure.
    """
    clean_user = username.strip().lower()
    if user_exists(clean_user):
        return False, f"Username '{clean_user}' already exists in database."

    display_name = name.strip() if name and name.strip() else clean_user.capitalize()
    hashed_pwd = generate_password_hash(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
        (clean_user, hashed_pwd, display_name, role)
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()

    return True, {
        'id': user_id,
        'username': clean_user,
        'name': display_name,
        'role': role
    }


def add_security_log(username, input_text, detection_type, risk_level, action):
    """
    Inserts a security event into the security_logs table.
    CRITICAL: Never pass passwords into input_text.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_logs (username, input_text, detection_type, risk_level, action)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        username or 'Anonymous/Unknown',
        input_text,
        detection_type,
        risk_level,
        action
    ))
    conn.commit()
    conn.close()


def get_security_logs(limit=50, username=None):
    """
    Retrieves recent security logs.
    If username is provided, filters logs for that specific user.
    Otherwise returns logs across the system (for Admins).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if username:
        cursor.execute('''
            SELECT * FROM security_logs 
            WHERE username = ? 
            ORDER BY id DESC LIMIT ?
        ''', (username, limit))
    else:
        cursor.execute('''
            SELECT * FROM security_logs 
            ORDER BY id DESC LIMIT ?
        ''', (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs


def get_security_stats():
    """
    Computes statistical counts for the dashboard overview.
    Returns a dictionary of total, safe, flagged, and blocked counts.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'BLOCKED'")
    blocked_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'FLAGGED'")
    flagged_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE action IN ('ALLOWED', 'LOGIN SUCCESS')")
    allowed_count = cursor.fetchone()[0]

    conn.close()
    return {
        'total': total_events,
        'blocked': blocked_count,
        'flagged': flagged_count,
        'allowed': allowed_count
    }


def clear_security_logs():
    """
    Clears all security logs (Admin utility).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_logs")
    conn.commit()
    conn.close()
