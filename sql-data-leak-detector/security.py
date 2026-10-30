"""
security.py - Security Analysis Engine: SQL Injection & DLP Detection
======================================================================
This module implements the core detection algorithms for:
1. SQL Injection (SQLi) pattern detection.
2. Data Loss Prevention (DLP) for identifying sensitive personal data
   (Phone Numbers, Email Addresses, and Credit Card numbers).
3. Risk Classification Matrix:
   - LOW     / ALLOWED : Clean input
   - MEDIUM  / FLAGGED : Moderate sensitive data (e.g., Email Address)
   - HIGH    / FLAGGED : High-risk sensitive data (e.g., Phone Number, Credit Card)
   - HIGH    / BLOCKED : Malicious SQL Injection attempt
   - CRITICAL/ BLOCKED : Multiple severe threats simultaneously

======================================================================
IMPORTANT NOTE FOR STUDENTS AND TEACHERS (VIVA POINT):
- Pattern matching and regular expressions used here are for educational
  demonstration to show how a Web Application Firewall (WAF) or Data Loss
  Prevention (DLP) filter inspects user payloads before processing.
- In production, pattern matching alone is NOT enough for SQL security.
  Applications MUST always use Parameterized Queries (Prepared Statements),
  which treat user input strictly as data, rendering SQL injection impossible.
======================================================================
"""

import re

# ----------------------------------------------------------------------
# 1. SQL Injection Signatures (Case-Insensitive Regex Patterns)
# ----------------------------------------------------------------------
SQLI_PATTERNS = [
    # Classic boolean tautology: ' OR '1'='1', ' OR 1=1, or 1=1
    (r"'\s*OR\s*'1'\s*=\s*'1", "' OR '1'='1' (Boolean Tautology)"),
    (r"'\s*OR\s+1\s*=\s*1", "' OR 1=1 (Boolean Tautology)"),
    (r"\bOR\s+1\s*=\s*1\b", "OR 1=1 (Boolean Expression)"),
    (r"'\s*OR\s+'[^']+'\s*=\s*'[^']+", "' OR 'a'='a' (Tautology)"),

    # SQL Comment truncation: admin' -- or admin'/*
    (r"\badmin'\s*--", "admin' -- (Auth Bypass via SQL Comment)"),
    (r"'\s*--", "' -- (SQL Line Comment Termination)"),
    (r"/\*.*?\*/", "/* */ (SQL Block Comment)"),

    # UNION SELECT attacks for data exfiltration
    (r"'\s*UNION\s+SELECT\b", "' UNION SELECT (Data Exfiltration)"),
    (r"\bUNION\s+SELECT\b", "UNION SELECT (Data Exfiltration)"),
    (r"\bUNION\s+ALL\s+SELECT\b", "UNION ALL SELECT"),

    # Destructive DDL and DML operations
    (r"\bDROP\s+TABLE\b", "DROP TABLE (Database Destruction)"),
    (r"\bDELETE\s+FROM\b", "DELETE FROM (Data Deletion)"),
    (r"\bINSERT\s+INTO\b", "INSERT INTO (Unauthorized Insertion)"),
    (r"\bUPDATE\s+\w+\s+SET\b", "UPDATE ... SET (Data Tampering)"),
    (r"\bUPDATE\s+users\b", "UPDATE users (User Table Tampering)"),
    
    # Generic stacked queries or tautology operators
    (r";\s*DROP\b", "Stacked Query (; DROP)"),
    (r";\s*SHUTDOWN\b", "Stacked Query (; SHUTDOWN)"),
    (r"\bEXEC(\s+|\()+", "EXEC / Stored Procedure Call")
]

# ----------------------------------------------------------------------
# 2. Data Loss Prevention (DLP) Regex Signatures
# ----------------------------------------------------------------------
# Phone number: 10-digit formats (e.g. 9876543210, 987-654-3210, +91 9876543210)
REGEX_PHONE = re.compile(
    r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\d{10}\b'
)

# Email address pattern: user@domain.tld
REGEX_EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# Credit card number pattern: 13-19 digits, grouped in 4s or contiguous
REGEX_CREDIT_CARD = re.compile(
    r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b'
)


def detect_sql_injection(input_text):
    """
    Scans input string for suspicious SQL Injection signatures.
    Returns: (is_sqli, matched_patterns)
    """
    if not input_text or not isinstance(input_text, str):
        return False, []

    matches = []
    for pattern, description in SQLI_PATTERNS:
        if re.search(pattern, input_text, re.IGNORECASE):
            matches.append(description)

    return (len(matches) > 0), matches


def detect_unusual_characters(username):
    """
    Scans username for unusual, restricted, or special characters and SQL injection attempts.
    Standard safe username: letters (a-z, A-Z), numbers (0-9), and underscores (_).
    Any special characters (quotes, dashes, comments, symbols, spaces, operators) are blocked.
    
    Returns:
        dict: {
            'has_unusual': bool,
            'special_chars': list of detected characters,
            'sqli_matches': list of SQLi pattern descriptions,
            'keyword_matches': list of disallowed SQL keywords,
            'reasons': list of summary explanations,
            'risk_level': 'CRITICAL' | 'HIGH' | 'LOW',
            'action': 'BLOCKED' | 'ALLOWED',
            'explanation': str
        }
    """
    if not username or not isinstance(username, str):
        return {
            'has_unusual': False,
            'special_chars': [],
            'sqli_matches': [],
            'keyword_matches': [],
            'reasons': [],
            'risk_level': 'LOW',
            'action': 'ALLOWED',
            'explanation': 'Empty or non-string input.'
        }

    # 1. Detect any non-alphanumeric and non-underscore characters
    # (e.g., quotes, hyphens, semicolons, brackets, spaces, slashes, mathematical/logic operators, symbols)
    raw_special = re.findall(r'[^a-zA-Z0-9_]', username)
    special_chars = sorted(list(set(raw_special)))

    # 2. Check for SQL Injection patterns
    is_sqli, sqli_matches = detect_sql_injection(username)

    # 3. Check for standalone SQL command keywords in username
    keyword_matches = list(set(re.findall(
        r'\b(OR|AND|UNION|SELECT|DROP|INSERT|DELETE|UPDATE|EXEC|SHUTDOWN|WHERE|FROM|LIMIT)\b',
        username,
        re.IGNORECASE
    )))

    reasons = []
    has_unusual = False

    if is_sqli:
        has_unusual = True
        reasons.append(f"SQL Injection attack detected: {', '.join(sqli_matches)}")

    if special_chars:
        has_unusual = True
        display_chars = [f"'{c}'" if c != ' ' else "'space'" for c in special_chars]
        reasons.append(f"Restricted special characters found: {', '.join(display_chars)}")

    if keyword_matches:
        has_unusual = True
        reasons.append(f"Disallowed database command keyword(s): {', '.join(keyword_matches)}")

    if has_unusual:
        risk_level = 'CRITICAL' if (is_sqli or len(special_chars) > 3) else 'HIGH'
        return {
            'has_unusual': True,
            'special_chars': special_chars,
            'sqli_matches': sqli_matches,
            'keyword_matches': keyword_matches,
            'reasons': reasons,
            'risk_level': risk_level,
            'action': 'BLOCKED',
            'explanation': 'Input blocked: Username contains unusual characters, restricted special symbols, or SQL injection patterns. Database execution prevented.'
        }

    return {
        'has_unusual': False,
        'special_chars': [],
        'sqli_matches': [],
        'keyword_matches': [],
        'reasons': [],
        'risk_level': 'LOW',
        'action': 'ALLOWED',
        'explanation': 'Username format is clean (alphanumeric and underscores only).'
    }


def detect_dlp_sensitive_data(input_text):
    """
    Scans input string for sensitive personal information (DLP).
    Returns a dictionary of detections with detected tokens (masked for privacy).
    """
    if not input_text or not isinstance(input_text, str):
        return {
            'has_sensitive_data': False,
            'types': [],
            'findings': []
        }

    findings = []
    detected_types = []

    # Check Credit Card
    cc_matches = REGEX_CREDIT_CARD.findall(input_text)
    # Filter out plain short numbers that don't match credit card length (> 12 digits)
    cc_filtered = [m for m in cc_matches if len(re.sub(r'\D', '', m)) in (13, 15, 16, 19)]
    if cc_filtered:
        detected_types.append('Credit Card')
        for match in cc_filtered:
            clean_digits = re.sub(r'\D', '', match)
            masked = clean_digits[:4] + "****" + clean_digits[-4:]
            findings.append({
                'type': 'Credit Card',
                'severity': 'HIGH',
                'matched': masked
            })

    # Check Phone Numbers
    phone_matches = REGEX_PHONE.findall(input_text)
    # Ensure they are not false positives from credit cards
    valid_phones = []
    for p in phone_matches:
        digits_only = re.sub(r'\D', '', p)
        if len(digits_only) == 10:
            valid_phones.append(p)
    if valid_phones:
        detected_types.append('Phone Number')
        for match in valid_phones:
            digits = re.sub(r'\D', '', match)
            masked = digits[:2] + "******" + digits[-2:]
            findings.append({
                'type': 'Phone Number',
                'severity': 'HIGH',
                'matched': masked
            })

    # Check Email Addresses
    email_matches = REGEX_EMAIL.findall(input_text)
    if email_matches:
        detected_types.append('Email Address')
        for match in email_matches:
            parts = match.split('@')
            masked = parts[0][:2] + "***@" + parts[1]
            findings.append({
                'type': 'Email Address',
                'severity': 'MEDIUM',
                'matched': masked
            })

    has_sensitive = len(findings) > 0
    return {
        'has_sensitive_data': has_sensitive,
        'types': detected_types,
        'findings': findings
    }


def analyze_security_risk(input_text):
    """
    Comprehensive Security Checker:
    Executes both SQL Injection Detection and Data Loss Prevention (DLP),
    then computes the unified Risk Classification and Action.

    Risk Levels:
    - LOW      : Normal clean input -> Action: ALLOWED
    - MEDIUM   : Email address found -> Action: FLAGGED
    - HIGH     : Phone Number or Credit Card found -> Action: FLAGGED
    - HIGH     : SQL Injection signature detected -> Action: BLOCKED
    - CRITICAL : Both SQLi and sensitive data found, or multiple SQLi attacks -> Action: BLOCKED

    Returns a standardized dictionary with all evaluation metadata.
    """
    if input_text is None:
        input_text = ""

    is_sqli, sqli_matches = detect_sql_injection(input_text)
    dlp_results = detect_dlp_sensitive_data(input_text)

    # 1. Multiple serious threats -> CRITICAL & BLOCKED
    if is_sqli and dlp_results['has_sensitive_data']:
        return {
            'is_safe': False,
            'detection_type': 'Multiple Threats (SQLi + Sensitive Data)',
            'risk_level': 'CRITICAL',
            'action': 'BLOCKED',
            'matched_patterns': sqli_matches + [f['type'] for f in dlp_results['findings']],
            'findings': dlp_results['findings'],
            'explanation': 'Compound security violation: Input contained both unauthorized SQL injection patterns and sensitive personal data. Immediately blocked.'
        }

    # 2. SQL Injection detected -> HIGH or CRITICAL & BLOCKED
    if is_sqli:
        risk = 'CRITICAL' if len(sqli_matches) >= 3 else 'HIGH'
        return {
            'is_safe': False,
            'detection_type': 'SQL Injection',
            'risk_level': risk,
            'action': 'BLOCKED',
            'matched_patterns': sqli_matches,
            'findings': [],
            'explanation': f"Malicious database command pattern detected: {', '.join(sqli_matches)}. Request blocked before executing any database operation."
        }

    # 3. Sensitive Data detected (DLP) -> MEDIUM / HIGH & FLAGGED
    if dlp_results['has_sensitive_data']:
        has_high_dlp = any(f['severity'] == 'HIGH' for f in dlp_results['findings'])
        risk = 'HIGH' if has_high_dlp else 'MEDIUM'
        primary_type = " & ".join(dlp_results['types'])

        return {
            'is_safe': False,
            'detection_type': primary_type,
            'risk_level': risk,
            'action': 'FLAGGED',
            'matched_patterns': [f['type'] + " (" + f['matched'] + ")" for f in dlp_results['findings']],
            'findings': dlp_results['findings'],
            'explanation': f"Data Loss Prevention (DLP) Alert: Found unencrypted sensitive information ({primary_type}). Request has been flagged for audit logging."
        }

    # 4. Clean Normal Input -> LOW & ALLOWED
    return {
        'is_safe': True,
        'detection_type': 'None',
        'risk_level': 'LOW',
        'action': 'ALLOWED',
        'matched_patterns': [],
        'findings': [],
        'explanation': 'Input is clean and safe. No SQL injection signatures or sensitive personal data patterns were detected.'
    }
