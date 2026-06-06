"""
analyzer.py — Password Strength Auditor
Scores passwords on entropy, patterns, and composition.
"""

import re
import math
import string


COMMON_PASSWORDS = {
    "password", "123456", "password1", "qwerty", "abc123",
    "letmein", "monkey", "master", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "welcome", "shadow", "superman", "michael", "football"
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qwer", "asdfgh",
    "1234", "12345", "123456", "654321", "0987"
]


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy bits of the password."""
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32  # common special chars

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def check_patterns(password: str) -> list:
    """Return a list of weaknesses found in the password."""
    issues = []
    pwd_lower = password.lower()

    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most commonly used passwords!")

    for pattern in KEYBOARD_PATTERNS:
        if pattern in pwd_lower:
            issues.append(f"Contains keyboard pattern: '{pattern}'")

    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains 3+ repeated characters in a row (e.g. 'aaa')")

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', pwd_lower):
        issues.append("Contains sequential pattern (e.g. '123' or 'abc')")

    if re.search(r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b', pwd_lower):
        issues.append("Contains a month name — easy to guess")

    if re.search(r'(19|20)\d{2}', password):
        issues.append("Contains a year — commonly used and easy to guess")

    return issues


def score_password(password: str) -> dict:
    """
    Full audit of a password. Returns a dict with:
      - score (0-100)
      - grade (F to A+)
      - entropy (bits)
      - issues (list of weaknesses)
      - suggestions (list of improvements)
      - breakdown (component scores)
    """
    if not password:
        return {"score": 0, "grade": "F", "entropy": 0,
                "issues": ["Password is empty"], "suggestions": [], "breakdown": {}}

    score = 0
    breakdown = {}
    suggestions = []

    # --- Length scoring (max 30 pts) ---
    length = len(password)
    if length >= 20:
        length_score = 30
    elif length >= 16:
        length_score = 25
    elif length >= 12:
        length_score = 20
    elif length >= 10:
        length_score = 15
    elif length >= 8:
        length_score = 10
    else:
        length_score = 5
        suggestions.append("Use at least 12 characters — longer is always stronger")
    breakdown["Length"] = f"{length_score}/30"
    score += length_score

    # --- Complexity scoring (max 40 pts) ---
    complexity_score = 0
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    if has_lower:
        complexity_score += 10
    else:
        suggestions.append("Add lowercase letters")
    if has_upper:
        complexity_score += 10
    else:
        suggestions.append("Add uppercase letters")
    if has_digit:
        complexity_score += 10
    else:
        suggestions.append("Add numbers")
    if has_special:
        complexity_score += 10
    else:
        suggestions.append("Add special characters like !@#$%^&*")
    breakdown["Complexity"] = f"{complexity_score}/40"
    score += complexity_score

    # --- Entropy scoring (max 20 pts) ---
    entropy = calculate_entropy(password)
    if entropy >= 80:
        entropy_score = 20
    elif entropy >= 60:
        entropy_score = 15
    elif entropy >= 40:
        entropy_score = 10
    elif entropy >= 28:
        entropy_score = 5
    else:
        entropy_score = 0
    breakdown["Entropy"] = f"{entropy_score}/20  ({entropy:.1f} bits)"
    score += entropy_score

    # --- Pattern penalty (max -30 pts) ---
    issues = check_patterns(password)
    penalty = min(len(issues) * 10, 30)
    score = max(0, score - penalty)
    if issues:
        breakdown["Pattern penalty"] = f"-{penalty} pts"

    # Determine grade
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "entropy": round(entropy, 1),
        "issues": issues,
        "suggestions": suggestions,
        "breakdown": breakdown
    }
