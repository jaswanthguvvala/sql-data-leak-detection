# SQL-Based Data Leak Detection & Prevention System
**Educational Prototype for College Mini-Project (3rd Year B.Tech CSE - AIML)**

---

## 1. Project Title
**SQL-Based Data Leak Detection & Prevention System**  
A lightweight, offline-ready web security prototype built using **Python, Flask, SQLite, HTML5, CSS3, and JavaScript** that demonstrates proactive threat detection, Data Loss Prevention (DLP), risk classification, and audit logging.

---

## 2. Problem Statement
Modern web applications frequently handle confidential user data and interact with backend databases using SQL queries. Two primary data security threats jeopardize these systems:
1. **SQL Injection (SQLi):** Malicious inputs crafted by attackers to manipulate database queries, bypass authentication, and view or alter unauthorized records.
2. **Sensitive Data Exposure / Data Leaks:** Unintentional or unauthorized transmission of personally identifiable information (PII) such as phone numbers, email addresses, or payment card numbers into unauthorized channels or insecure storage.

Traditional applications often attempt to authenticate inputs directly against the database without an intermediary inspection layer, leading to catastrophic security breaches.

---

## 3. Objective
The objective of this mini-project is to build and demonstrate a multi-layered security pipeline:
$$\text{User Login} \longrightarrow \text{Security Check} \longrightarrow \text{SQLi + DLP Detection} \longrightarrow \text{Risk Classification} \longrightarrow \text{Allow / Flag / Block} \longrightarrow \text{Security Logging}$$

**Core Goals:**
- Intercept user input **before** it touches the database.
- Identify SQL Injection attack patterns (tautologies, comment delimiters, union attacks) in a case-insensitive manner.
- Detect sensitive data leakage (Phone numbers, Emails, Credit cards) using regular expressions (DLP).
- Classify threats into distinct risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Block malicious attempts and flag sensitive exposures.
- Audit every event inside a local SQLite database (`security_logs`) without exposing passwords.

---

## 4. Technologies Used
- **Python 3**: Core backend programming language, string parsing, and regex engine.
- **Flask**: Lightweight WSGI web framework for routing, session management, and template rendering.
- **SQLite 3**: Serverless, self-contained relational database management system.
- **Werkzeug Security**: Secure password hashing using PBKDF2/SHA256 (`generate_password_hash` and `check_password_hash`).
- **HTML5 & CSS3**: Modern, responsive user interface with cybersecurity color semantics (Safe, Flagged, Blocked).
- **Vanilla JavaScript**: Lightweight client-side helper for one-click demo presets and table filtering.

### Mapping of Technologies to Concepts
| Technology | Role & Implementation Location |
| :--- | :--- |
| **Python** | Backend security logic & pattern matching (`security.py`, `database.py`) |
| **Flask** | Web application routing, session cookies, and controllers (`app.py`) |
| **HTML5 / CSS3** | User interface, responsive styling, and visual status badges (`templates/`, `static/`) |
| **SQLite 3** | Local relational data store (`database/security.db`) |
| **SQL** | Parameterized queries for user lookup and security audit logging |
| **SQL Injection Detection** | Security engine signature matching (`security.py -> detect_sql_injection`) |
| **DLP (Data Loss Prevention)** | Regular expression scanner for PII (`security.py -> detect_dlp_sensitive_data`) |
| **Risk Analysis** | Multi-factor risk classification engine (`security.py -> analyze_security_risk`) |
| **Blocking Mechanism** | Pre-authentication interception rejecting bad requests (`app.py -> login`) |
| **Security Logging** | Persistent event storage in the `security_logs` table (`database.py -> add_security_log`) |
| **Cloud Computing** | Deployment and scalability architecture concept (explained below) |

---

## 5. Project Architecture

```
                 USER
                   |
                   ↓
              LOGIN PAGE
                   |
                   ↓
           SECURITY CHECKER
            /             \
           /               \
          ↓                 ↓
 SQL INJECTION              DLP
    CHECK                  CHECK
          \                 /
           \               /
            ↓             ↓
             RISK ANALYSIS
                   |
          -------------------
          |                 |
          ↓                 ↓
       BLOCKED            ALLOWED
                              |
                              ↓
                       SQLite Database
                              |
                              ↓
                       SECURITY LOG
```

### Flow Breakdown:
1. The **User** interacts with the **Login Page** or the in-dashboard **Security Inspector**.
2. All submitted inputs are passed directly to the **Security Checker** before any database operations occur.
3. The checker performs simultaneous checks:
   - **SQL Injection Check:** Scans for known SQL exploit signatures.
   - **DLP Check:** Scans for unencrypted personal data (Phone, Email, Credit Card).
4. The **Risk Analysis Engine** evaluates the findings and outputs a risk rating and action.
5. If **BLOCKED**, execution halts immediately and the incident is recorded in the `security_logs`. The payload is never sent to SQLite.
6. If **ALLOWED**, the sanitized credentials undergo parameterized SQL authentication against the `users` table.

---

## 6. Login Authentication Flow
1. User enters `Username` and `Password`.
2. **Pre-check:** `security.analyze_security_risk(username)` evaluates the username.
3. If suspicious tokens (`' OR '1'='1`, `admin' --`) are detected:
   - The request is **BLOCKED**.
   - A security event is logged in `security_logs` with `Action: BLOCKED` and `Risk: HIGH`.
   - The user is shown `⚠️ SUSPICIOUS INPUT DETECTED`.
   - **No query is executed against SQLite.**
4. If input is clean:
   - The system executes a parameterized query: `SELECT * FROM users WHERE username = ?`.
   - The stored password hash is validated against the entered password using `check_password_hash()`.
5. If credentials are correct:
   - Sets secure session cookie (`user_id`, `username`, `name`, `role`).
   - Logs `LOGIN SUCCESS` with `Risk: LOW` and `Action: LOGIN SUCCESS`.
   - Displays `✅ LOGIN SUCCESSFUL` and redirects to the **Dashboard**.
6. If credentials are incorrect:
   - Logs `LOGIN FAILED` with `Risk: LOW` and `Action: LOGIN FAILED`.
   - Displays `❌ LOGIN FAILED: Invalid username or password`.

---

## 7. SQLite Database Schema
The database file `database/security.db` is initialized automatically on app startup.

### 1. `users` Table
Stores registered system accounts:
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL
);
```

### 2. `security_logs` Table
Stores all audit and security inspection records:
```sql
CREATE TABLE security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    input_text TEXT,
    detection_type TEXT,
    risk_level TEXT,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

> **Security Rule:** Passwords are never stored in plain text (they use salted cryptographic hashes) and are **never** logged to `security_logs`.

---

## 8. SQL Injection Detection Mechanism
Located in: [`security.py`](security.py)

The system detects common SQL injection attack vectors using case-insensitive regular expressions:
- **Tautologies (Always True conditions):**
  - `' OR '1'='1`
  - `' OR 1=1`
  - `OR 1=1`
  - `' OR 'a'='a'`
- **Authentication Bypass & Comment Delimiters:**
  - `admin' --`
  - `' --`
  - `/* ... */`
- **Data Exfiltration (UNION queries):**
  - `' UNION SELECT`
  - `UNION SELECT`
  - `UNION ALL SELECT`
- **Destructive DDL/DML Commands:**
  - `DROP TABLE`
  - `DELETE FROM`
  - `INSERT INTO`
  - `UPDATE users`
  - `; DROP` / `; SHUTDOWN`

> **Viva Note for Students & Teachers:**  
> Pattern matching in this project is an educational demonstration of how a Web Application Firewall (WAF) inspects incoming payloads. In production applications, developers must always use **Parameterized Queries (Prepared Statements)** so that user input is treated strictly as data literals and can never alter the SQL command structure.

---

## 9. Data Loss Prevention (DLP) Mechanism
Located in: [`security.py`](security.py)

The DLP module scans inputs for sensitive personal data to prevent unauthorized leaks:
1. **Phone Numbers:** Scans for 10-digit mobile numbers (e.g., `9876543210`, `+91-9876543210`).
   - *Severity:* `HIGH`
   - *Action:* `FLAGGED`
2. **Email Addresses:** Scans for valid email patterns (`user@domain.ext`).
   - *Severity:* `MEDIUM`
   - *Action:* `FLAGGED`
3. **Credit-Card-Like Numbers:** Scans for 13 to 19 digit grouped numbers (e.g., `4532 8901 2345 6789`).
   - *Severity:* `HIGH`
   - *Action:* `FLAGGED`

*Privacy Safeguard:* Detected numbers and emails are masked in reports (e.g., `98******10`, `ha***@example.com`) to avoid displaying personal information.

---

## 10. Risk Classification Matrix

| Scenario | Detection Type | Risk Level | Action |
| :--- | :--- | :---: | :---: |
| Normal text, benign search query | `None` | `LOW` | `ALLOWED` |
| Valid user authentication | `None` | `LOW` | `LOGIN SUCCESS` |
| Email address exposed in input | `Email Address` | `MEDIUM` | `FLAGGED` |
| Phone number exposed in input | `Phone Number` | `HIGH` | `FLAGGED` |
| Credit card number exposed | `Credit Card` | `HIGH` | `FLAGGED` |
| SQL Injection pattern detected | `SQL Injection` | `HIGH` | `BLOCKED` |
| SQLi combined with DLP or 3+ SQLi tokens | `Multiple Threats` | `CRITICAL` | `BLOCKED` |

---

## 11. Blocking vs. Flagging Logic
- **`BLOCKED`:** Applied to active security threats (such as SQL Injection). The server rejects the request immediately. The suspicious string is **never passed to the database execution engine**.
- **`FLAGGED`:** Applied to sensitive data transmissions (DLP). The data is logged for administrative audit so security officers can investigate potential unauthorized data dissemination.
- **`ALLOWED`:** Applied to clean, benign user inputs that pass all security checks.

---

## 12. Security Logging
Every security event is captured inside SQLite in the `security_logs` table:
- **Columns recorded:** `id`, `username`, `input_text`, `detection_type`, `risk_level`, `action`, `timestamp`.
- **Admin Visibility:** Administrators (`admin`) can view all recorded logs and clear logs for testing.
- **Privacy Protection:** User passwords are encrypted before storage and are never written to the logs.

---

## 13. Cloud Computing Concept

### Current Implementation vs. Cloud Deployment
> **Clarification:**  
> This mini-project is currently running **locally on your machine** (`http://127.0.0.1:5000`). It does **not** make external cloud API calls or require paid services. However, this application is designed following cloud-ready principles and can be easily deployed to a cloud server.

### Future Cloud Architecture Diagram
```
                     USER
                      ↓
                   Internet
                      ↓
       [ Cloud Server / VM or Container ]
       (e.g., AWS EC2, Azure VM, GCP Compute Engine)
                      ↓
              Flask Web Application
                      ↓
               Security Checker
              (SQLi + DLP Engine)
                      ↓
             [ Cloud Database ]
     (e.g., AWS RDS, Azure SQL, Managed Cloud DB)
```

### Advantages of Cloud Computing for this System:
1. **Remote Accessibility:** Users and administrators can access the security portal from any device worldwide via the Internet.
2. **Centralized Hosting:** Security policies, DLP rules, and audit logs are managed centrally without needing software installed on every client machine.
3. **Elastic Scalability:** When query traffic spikes, cloud auto-scaling can launch additional application instances behind a Cloud Load Balancer.
4. **Database Hosting & High Availability:** Managed cloud databases provide automatic backups, multi-region replication, and failover protection.
5. **Continuous Availability (99.9% Uptime):** Cloud data centers provide redundant power, networking, and hardware to guarantee uninterrupted service.

---

## 14. Installation
This project requires only standard Python and Flask.

### Step 1: Open Terminal / PowerShell
Navigate to the project directory:
```bash
cd "sql-data-leak-detector"
```

### Step 2: Install Required Package
```bash
pip install -r requirements.txt
```
*(Flask is the only dependency. SQLite and regex are built into standard Python).*

---

## 15. How to Run
Run the Flask application:
```bash
python app.py
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 16. Sample Usernames and Passwords
The application automatically seeds three sample user accounts upon startup:

| Username | Password | Full Name | Role | Access Level |
| :--- | :--- | :--- | :--- | :--- |
| **`harsha`** | `harsha123` | Harsha | Student | Standard User & Tester |
| **`admin`** | `admin123` | Administrator | Admin | System Auditor (View all logs & clear) |
| **`student`** | `student123` | Student User | Student | Standard User |

*(Note: Passwords are automatically hashed using PBKDF2/SHA-256 before insertion).*

---

## 17. College Test Cases & Verification

### Test Case 1: Correct Login
- **Username:** `harsha`
- **Password:** `harsha123`
- **Action:** Click `[ LOGIN ]`
- **Expected Result:**
  ```
  ✅ LOGIN SUCCESSFUL
  Welcome, Harsha!
  Role: Student
  Redirects to Security Dashboard (Security Status: 🟢 SAFE)
  ```

### Test Case 2: Wrong Password
- **Username:** `harsha`
- **Password:** `wrong123`
- **Action:** Click `[ LOGIN ]`
- **Expected Result:**
  ```
  ❌ LOGIN FAILED
  Invalid username or password.
  ```

### Test Case 3: SQL Injection Detection (Tautology)
- **Input (in Login username or Live Inspector):**
  ```sql
  ' OR '1'='1
  ```
- **Password (if testing login):** `anything`
- **Expected Result:**
  ```
  ⚠️ SUSPICIOUS INPUT DETECTED
  Detection Type: SQL Injection
  Risk Level: HIGH
  Action: BLOCKED
  (Request blocked without executing query)
  ```

### Test Case 4: SQL Injection Detection (Comment Delimiter)
- **Input:**
  ```sql
  admin' --
  ```
- **Password:** `anything`
- **Expected Result:**
  ```
  ⚠️ SUSPICIOUS INPUT DETECTED
  Detection Type: SQL Injection
  Risk Level: HIGH
  Action: BLOCKED
  ```

### Test Case 5: DLP Sensitive Data Detection (Phone Number)
- **Input (in Live Inspector on Dashboard):**
  ```text
  My phone number is 9876543210
  ```
- **Expected Result:**
  ```
  🚨 SENSITIVE DATA DETECTED
  Type: Phone Number
  Risk Level: HIGH
  Action: FLAGGED
  ```

### Test Case 6: Normal Clean Input
- **Input (in Live Inspector on Dashboard):**
  ```text
  Please check my order status
  ```
- **Expected Result:**
  ```
  ✅ SAFE
  Detection Type: None
  Risk Level: LOW
  Action: ALLOWED
  ```

---

## 18. Expected Outputs Summary Table

| Test Case | Tested String | Expected Detection | Risk Level | Action | System Status |
| :---: | :--- | :--- | :---: | :---: | :---: |
| **1** | `harsha` / `harsha123` | `None` | `LOW` | `LOGIN SUCCESS` | `🟢 SAFE` |
| **2** | `harsha` / `wrong123` | `None` | `LOW` | `LOGIN FAILED` | `❌ REJECTED` |
| **3** | `' OR '1'='1` | `SQL Injection` | `HIGH` | `BLOCKED` | `🛑 BLOCKED` |
| **4** | `admin' --` | `SQL Injection` | `HIGH` | `BLOCKED` | `🛑 BLOCKED` |
| **5** | `My phone number is 9876543210` | `Phone Number` | `HIGH` | `FLAGGED` | `🚩 FLAGGED` |
| **6** | `Please check my order status` | `None` | `LOW` | `ALLOWED` | `🟢 SAFE` |

---

## 19. Limitations
1. **Heuristic / Signature-Based Detection:** Regex pattern matching only catches known attack signatures. Novel obfuscated SQLi techniques might evade basic regex without deep syntax tree parsing.
2. **Local In-Memory / File SQLite:** Designed for single-server or local testing; not intended for high-concurrency production enterprise write workloads.
3. **Simulated DLP:** Scans typical Indian/US phone formats, standard emails, and standard credit card lengths. It does not perform full bank issuer validation (Luhn algorithm).

---

## 20. Future Enhancements
1. **Cloud Deployment:** Deploy the Flask application to **AWS Elastic Beanstalk** or an **Azure App Service** container backed by an **AWS RDS PostgreSQL/MySQL** cloud database.
2. **Machine Learning / AI-Based Anomaly Detection:** Train a TF-IDF + Logistic Regression or Transformer model to detect zero-day SQL injection attacks based on semantic token distribution.
3. **Advanced DLP Masking Engine:** Integrate automatic real-time tokenization and dynamic data masking (DDM) for PII fields before saving to the database.
4. **Multi-Factor Authentication (MFA):** Add email or TOTP-based 2FA for administrative logins.
5. **Real-time Security Alerts:** Integrate automated email or webhook alerts (e.g., Slack or Twilio SMS) when a `CRITICAL` or `BLOCKED` event occurs.

---

### Project Structure Reference
```
sql-data-leak-detector/
│
├── app.py                  # Main Flask application controller & routes
├── database.py             # SQLite setup, schema, sample accounts, and queries
├── security.py             # SQL injection detection, regex DLP, and risk matrix
├── requirements.txt        # Flask dependency list
├── README.md               # Complete project documentation & viva guide
│
├── database/
│   └── security.db         # SQLite database file (auto-generated)
│
├── templates/
│   ├── login.html          # Login view with WAF interception
│   ├── dashboard.html      # Security dashboard, test inspector, and audit table
│   └── result.html         # Threat inspection report card
│
└── static/
    ├── style.css           # Modern dark-theme stylesheet
    └── script.js           # Interactive test presets & table filtering
```
