"""
Breach Checker Module - Cloud Security Analyzer (CSA)
Uses HaveIBeenPwned API v3 for email breach checking
Uses k-anonymity model for password checking (password never sent to server)

Privacy: Only first 5 chars of SHA1 hash sent for password checks.
Email checks use HIBP public API (free tier available).
"""

import hashlib
import urllib.request
import urllib.error
import json
import time


HIBP_EMAIL_URL  = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
HIBP_PWNED_URL  = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breach/{name}"

# HIBP requires a user-agent and optionally an API key for email checks
USER_AGENT = "CSA-CloudSecurityAnalyzer/1.0 (University of Wah FYP)"


def check_email_breaches(email: str, api_key: str = None) -> dict:
    """
    Check if an email has been in any known data breaches.
    Requires HIBP API key for email lookups (free at haveibeenpwned.com/API/Key).
    Falls back to demo data if no key provided.
    """
    if not email or '@' not in email:
        return {'error': 'Invalid email address'}

    headers = {
        'User-Agent': USER_AGENT,
        'hibp-api-key': api_key or '',
    }

    url = HIBP_EMAIL_URL.format(email=urllib.parse.quote(email))

    try:
        import urllib.parse
        url = HIBP_EMAIL_URL.format(email=urllib.parse.quote(email))
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return {
                'found': True,
                'breach_count': len(data),
                'breaches': data,
                'email': email
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'found': False, 'breach_count': 0, 'breaches': [], 'email': email}
        elif e.code == 401:
            return {'error': 'HIBP API key required or invalid. Get a free key at haveibeenpwned.com/API/Key', 'email': email}
        elif e.code == 429:
            return {'error': 'Rate limit exceeded. Please wait a moment and try again.', 'email': email}
        else:
            return {'error': f'API error: {e.code}', 'email': email}
    except Exception as e:
        return {'error': f'Connection failed: {str(e)}', 'email': email}


def check_password_pwned(password: str) -> dict:
    """
    Check if a password has appeared in known data breaches.
    Uses k-anonymity: only first 5 chars of SHA1 hash are sent to HIBP.
    The actual password NEVER leaves your device.
    """
    if not password:
        return {'error': 'No password provided'}

    # SHA1 hash the password
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        url = HIBP_PWNED_URL.format(prefix=prefix)
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()

        # Check if our suffix appears in results
        for line in body.splitlines():
            parts = line.split(':')
            if len(parts) == 2:
                hash_suffix, count = parts[0].strip(), int(parts[1].strip())
                if hash_suffix == suffix:
                    return {
                        'pwned': True,
                        'count': count,
                        'message': f'This password has appeared {count:,} times in data breaches!',
                        'severity': 'critical' if count > 100 else 'high'
                    }

        return {
            'pwned': False,
            'count': 0,
            'message': 'Good news! This password was not found in any known data breaches.',
            'severity': 'safe'
        }
    except Exception as e:
        return {'error': f'Connection failed: {str(e)}'}


def check_password_strength(password: str) -> dict:
    """Analyze password strength locally."""
    if not password:
        return {'score': 0, 'label': 'Empty', 'color': 'gray', 'tips': []}

    score = 0
    tips = []

    # Length checks
    length = len(password)
    if length >= 8:  score += 1
    else: tips.append('Use at least 8 characters')
    if length >= 12: score += 1
    else: tips.append('12+ characters is much stronger')
    if length >= 16: score += 1

    # Character variety
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

    if has_upper and has_lower: score += 1
    else: tips.append('Mix uppercase and lowercase letters')
    if has_digit: score += 1
    else: tips.append('Add numbers')
    if has_special: score += 1
    else: tips.append('Add special characters (!@#$...)')

    # Common patterns
    common = ['password','123456','qwerty','abc123','admin','letmein','welcome','monkey']
    if password.lower() in common:
        score = max(0, score - 3)
        tips.insert(0, 'Avoid common passwords!')

    # Repeated chars
    if len(set(password)) < len(password) * 0.4:
        score = max(0, score - 1)
        tips.append('Avoid repeated characters')

    # Score → label
    if score >= 6:
        label, color, pct = 'Very Strong', '#3fb950', 100
    elif score >= 5:
        label, color, pct = 'Strong', '#58a6ff', 80
    elif score >= 4:
        label, color, pct = 'Moderate', '#d29922', 60
    elif score >= 3:
        label, color, pct = 'Weak', '#fd7e14', 40
    else:
        label, color, pct = 'Very Weak', '#f85149', 20

    return {
        'score': score, 'max_score': 7,
        'label': label, 'color': color,
        'percentage': pct,
        'length': length,
        'has_upper': has_upper, 'has_lower': has_lower,
        'has_digit': has_digit, 'has_special': has_special,
        'tips': tips
    }


# ── urllib.parse was used above, need to import it properly ──────────────────
import urllib.parse

# ── Demo/fallback data for when HIBP API key is not set ─────────────────────
DEMO_BREACHES = {
    'test@example.com': {
        'found': True, 'breach_count': 3, 'email': 'test@example.com',
        'breaches': [
            {
                'Name': 'Adobe', 'Title': 'Adobe',
                'Domain': 'adobe.com',
                'BreachDate': '2013-10-04',
                'AddedDate': '2013-12-04T00:00:00Z',
                'ModifiedDate': '2022-05-15T23:52:49Z',
                'PwnCount': 152445165,
                'Description': 'In October 2013, 153 million Adobe accounts were breached with each record containing an internal ID, username, email, encrypted password and a password hint in plain text.',
                'DataClasses': ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
                'IsVerified': True, 'IsFabricated': False, 'IsSensitive': False,
                'IsSpamList': False, 'LogoPath': ''
            },
            {
                'Name': 'LinkedIn', 'Title': 'LinkedIn',
                'Domain': 'linkedin.com',
                'BreachDate': '2012-05-05',
                'AddedDate': '2016-05-22T00:00:00Z',
                'PwnCount': 164611595,
                'Description': 'In May 2016, LinkedIn had 164 million email addresses and passwords exposed. Originally hacked in 2012, the data remained out of sight until being offered for sale on a dark market site.',
                'DataClasses': ['Email addresses', 'Passwords'],
                'IsVerified': True, 'IsFabricated': False, 'IsSensitive': False,
                'IsSpamList': False, 'LogoPath': ''
            },
            {
                'Name': 'Canva', 'Title': 'Canva',
                'Domain': 'canva.com',
                'BreachDate': '2019-05-24',
                'AddedDate': '2019-08-06T10:44:56Z',
                'PwnCount': 137272116,
                'Description': 'In May 2019, the graphic design tool website Canva suffered a data breach that impacted 137 million users. Exposed data included email addresses, usernames, names and passwords.',
                'DataClasses': ['Email addresses', 'Names', 'Passwords', 'Usernames'],
                'IsVerified': True, 'IsFabricated': False, 'IsSensitive': False,
                'IsSpamList': False, 'LogoPath': ''
            }
        ]
    }
}
