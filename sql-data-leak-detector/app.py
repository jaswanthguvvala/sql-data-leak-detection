"""
app.py - Main Flask Application Controller
==========================================
SQL-Based Data Leak Detection & Prevention System
Beginner-friendly educational prototype for college mini-project.

Workflow Demonstrated:
User Login -> Security Check -> SQLi Detection + DLP Detection ->
Risk Classification -> Allow/Flag/Block -> Security Logging
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import database
import security

app = Flask(__name__)
# Secret key for secure session cookies
app.secret_key = 'cc_mini_project_sql_leak_detector_secret_key_harsha_2026'

# Ensure the database and sample accounts exist before handling requests
with app.app_context():
    database.init_db()


@app.context_processor
def inject_user():
    """Makes current user session info available to all Jinja2 templates."""
    return {
        'current_user': session.get('user')
    }


@app.route('/')
def index():
    """Root route: Redirects to dashboard if logged in, otherwise to login."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login Route:
    1. Intercepts username and scans for unusual or special characters and SQL injection.
    2. If unusual or special characters are detected -> BLOCKED (No DB query performed).
    3. Checks if user exists in SQLite database:
       - If does NOT exist -> REJECTED ('User does not exist').
       - If user DOES exist:
         -> Checks password with safe parameterized query and hash verification.
         -> If password is WRONG -> REJECTED / BLOCKED ('Unauthorized access to existing user').
         -> If password is CORRECT -> ACCEPTED -> Creates session & redirects to dashboard.
    """
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return render_template(
                'login.html',
                status_type='error',
                status_title='❌ Incomplete Credentials',
                status_message='Please enter both your username and password.',
                entered_username=username,
                active_tab='login'
            )

        # -------------------------------------------------------------
        # STEP 1: Unusual Characters & SQL Injection Interception
        # -------------------------------------------------------------
        unusual_check = security.detect_unusual_characters(username)
        sec_result = security.analyze_security_risk(username)

        if unusual_check['has_unusual'] or (not sec_result['is_safe'] and sec_result['action'] == 'BLOCKED'):
            # Blocked immediately! Input is never executed against the database.
            detected_chars = ", ".join([f"'{c}'" if c != ' ' else "'space'" for c in unusual_check.get('special_chars', [])])
            reasons_list = unusual_check.get('reasons', [])
            reason_str = " • ".join(reasons_list) if reasons_list else sec_result.get('explanation', 'Suspicious payload')

            database.add_security_log(
                username=username if len(username) <= 50 else username[:47] + "...",
                input_text=username,
                detection_type='Unusual Characters / SQLi Attempt',
                risk_level=unusual_check.get('risk_level', 'HIGH'),
                action='BLOCKED'
            )

            return render_template(
                'login.html',
                status_type='blocked',
                status_title='🛑 ACCESS BLOCKED: Unusual or Special Characters Detected',
                status_message=f"Access blocked for security: {reason_str}. Restricted characters found: [{detected_chars if detected_chars else 'SQL syntax'}]. Usernames may only contain alphanumeric characters and underscores.",
                entered_username=username,
                active_tab='login'
            )

        # -------------------------------------------------------------
        # STEP 2: Verify If User Exists in Database
        # -------------------------------------------------------------
        user_exists = database.user_exists(username)

        if not user_exists:
            # User does not exist in database
            database.add_security_log(
                username=username,
                input_text=f"Login attempt for non-existent account: '{username}'",
                detection_type='Account Not Found',
                risk_level='LOW',
                action='LOGIN REJECTED'
            )

            return render_template(
                'login.html',
                status_type='error',
                status_title='❌ ACCESS REJECTED: User Does Not Exist',
                status_message=f"The account '{username}' was not found in our database. Please check your username or create an account below.",
                entered_username=username,
                active_tab='login'
            )

        # -------------------------------------------------------------
        # STEP 3: Safe Parameterized Password Verification
        # -------------------------------------------------------------
        is_valid, user_data = database.verify_user_credentials(username, password)

        if not is_valid:
            # User exists, but password was wrong: Reject / block unauthorized attempt!
            database.add_security_log(
                username=username,
                input_text=f"Unauthorized password attempt on existing user: '{username}'",
                detection_type='Unauthorized Access to Existing Account',
                risk_level='MEDIUM',
                action='LOGIN REJECTED'
            )

            return render_template(
                'login.html',
                status_type='blocked',
                status_title='🛑 ACCESS REJECTED: Unauthorized Access Attempt',
                status_message=f"Access to existing account '{username}' was rejected. Incorrect password provided. Unauthorized access to existing user accounts is strictly blocked.",
                entered_username=username,
                active_tab='login'
            )

        # -------------------------------------------------------------
        # STEP 4: Login Accepted! User Exists & Password Matches
        # -------------------------------------------------------------
        session['user'] = {
            'id': user_data['id'],
            'username': user_data['username'],
            'name': user_data['name'],
            'role': user_data['role']
        }

        database.add_security_log(
            username=user_data['username'],
            input_text='User Authentication',
            detection_type='None',
            risk_level='LOW',
            action='LOGIN SUCCESS'
        )

        return redirect(url_for('dashboard'))

    return render_template('login.html', active_tab='login')


@app.route('/register', methods=['POST'])
def register():
    """
    User Registration Route:
    - Blocks any unusual or special characters in chosen username.
    - Rejects if username already exists in database.
    - Creates new account with securely hashed password if clean & unique.
    """
    username = request.form.get('reg_username', '').strip()
    password = request.form.get('reg_password', '').strip()
    name = request.form.get('reg_name', '').strip()

    if not username or not password:
        return render_template(
            'login.html',
            status_type='error',
            status_title='❌ Incomplete Information',
            status_message='Username and password are required for registration.',
            active_tab='register'
        )

    # 1. Unusual / Special characters inspection on registration
    unusual_check = security.detect_unusual_characters(username)
    if unusual_check['has_unusual']:
        detected_chars = ", ".join([f"'{c}'" if c != ' ' else "'space'" for c in unusual_check.get('special_chars', [])])
        database.add_security_log(
            username=username,
            input_text=username,
            detection_type='Unusual Characters in Registration',
            risk_level='HIGH',
            action='BLOCKED'
        )
        return render_template(
            'login.html',
            status_type='blocked',
            status_title='🛑 REGISTRATION BLOCKED: Unusual Characters Detected',
            status_message=f"Registration blocked: Usernames must only contain alphanumeric characters and underscores. Detected restricted characters: [{detected_chars}].",
            active_tab='register'
        )

    # 2. Check if username already exists
    if database.user_exists(username):
        database.add_security_log(
            username=username,
            input_text=f"Attempted to register already existing username: '{username}'",
            detection_type='Duplicate User Registration',
            risk_level='LOW',
            action='LOGIN REJECTED'
        )
        return render_template(
            'login.html',
            status_type='error',
            status_title='❌ REGISTRATION REJECTED: User Already Exists',
            status_message=f"The username '{username}' already exists in the database. Please choose a different username or sign in with your password.",
            active_tab='register'
        )

    # 3. Create account
    success, res = database.register_user(username, password, name=name, role='Student')
    if success:
        database.add_security_log(
            username=username,
            input_text=f"New user registered: '{username}'",
            detection_type='None',
            risk_level='LOW',
            action='USER REGISTERED'
        )
        return render_template(
            'login.html',
            status_type='success',
            status_title='✅ ACCOUNT CREATED SUCCESSFULLY',
            status_message=f"Account '{username}' was registered successfully! You can now sign in below.",
            entered_username=username,
            active_tab='login'
        )
    else:
        return render_template(
            'login.html',
            status_type='error',
            status_title='❌ Registration Error',
            status_message=str(res),
            active_tab='register'
        )


@app.route('/dashboard')
def dashboard():
    """
    Dashboard Route:
    Displays:
    - Welcome greeting, role, and '🟢 SAFE' security status.
    - Live Data Leak & SQLi Inspector for testing queries & text.
    - Recent Security Activity table.
    - If user is Admin, displays system-wide audit controls & stats.
    """
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    is_admin = (user['role'] == 'Admin')

    # Fetch logs: Admins see all logs, Students see their own activity plus recent public events
    if is_admin:
        logs = database.get_security_logs(limit=100)
    else:
        logs = database.get_security_logs(limit=50)

    stats = database.get_security_stats()

    return render_template(
        'dashboard.html',
        user=user,
        logs=logs,
        stats=stats,
        is_admin=is_admin
    )


@app.route('/inspect', methods=['POST'])
def inspect_input():
    """
    Interactive Live Security Inspector Route:
    Allows students and teachers to submit arbitrary SQL queries or text
    (e.g., Test 3, Test 4, Test 5, Test 6).
    The input is evaluated by security.py and logged into security_logs.
    """
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    test_input = request.form.get('test_input', '').strip()

    if not test_input:
        flash('Please enter text or a query to inspect.', 'warning')
        return redirect(url_for('dashboard'))

    # Run the Security Checker
    sec_result = security.analyze_security_risk(test_input)

    # Log the security inspection event
    database.add_security_log(
        username=user['username'],
        input_text=test_input,
        detection_type=sec_result['detection_type'],
        risk_level=sec_result['risk_level'],
        action=sec_result['action']
    )

    # Render the detailed report card
    return render_template(
        'result.html',
        result=sec_result,
        input_text=test_input,
        source='dashboard',
        user=user
    )


@app.route('/admin/clear-logs', methods=['POST'])
def clear_logs():
    """Admin-only utility to clear logs during testing/demonstrations."""
    if 'user' in session and session['user'].get('role') == 'Admin':
        database.clear_security_logs()
        flash('Security logs have been cleared successfully.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Logs the user out and clears the session."""
    session.clear()
    return redirect(url_for('login'))


# -------------------------------------------------------------
# Graceful Error Handlers (Prevents Python stack trace leakage)
# -------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template(
        'result.html',
        result={
            'is_safe': True,
            'detection_type': 'Page Not Found (404)',
            'risk_level': 'LOW',
            'action': 'ALLOWED',
            'matched_patterns': [],
            'explanation': 'The requested URL was not found on this server.'
        },
        input_text=request.path,
        source='error'
    ), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        'result.html',
        result={
            'is_safe': False,
            'detection_type': 'Internal Server Handled',
            'risk_level': 'MEDIUM',
            'action': 'FLAGGED',
            'matched_patterns': [],
            'explanation': 'An internal processing error occurred. Detailed stack traces are suppressed for security.'
        },
        input_text='',
        source='error'
    ), 500


if __name__ == '__main__':
    # Run locally on http://127.0.0.1:5000
    print("================================================================")
    print(" SQL-Based Data Leak Detection & Prevention System Starting... ")
    print(" Local URL: http://127.0.0.1:5000")
    print(" Default Accounts:")
    print("   1. Harsha   (Student) -> harsha / harsha123")
    print("   2. Admin    (Admin)   -> admin  / admin123")
    print("   3. Student  (Student) -> student/ student123")
    print("================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
