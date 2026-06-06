"""
pwned.py — HaveIBeenPwned API Checker
Uses the k-anonymity model: only the first 5 chars of the SHA-1 hash
are sent to the API, so your actual password never leaves your machine.
"""

import hashlib
import requests


def check_pwned(password: str) -> dict:
    """
    Check if a password appears in known data breaches via HIBP API.

    Uses k-anonymity: we hash the password, send only the first 5 chars
    of the hash to the API, then check the returned list locally.

    Returns:
        {
          "found": bool,
          "count": int,   # how many times seen in breaches
          "error": str or None
        }
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "PythonPasswordAuditor/1.0"},
            timeout=5
        )

        if response.status_code != 200:
            return {"found": False, "count": 0,
                    "error": f"API error: HTTP {response.status_code}"}

        # Each line: HASH_SUFFIX:COUNT
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {"found": True, "count": int(count), "error": None}

        return {"found": False, "count": 0, "error": None}

    except requests.exceptions.ConnectionError:
        return {"found": False, "count": 0,
                "error": "No internet connection — breach check skipped"}
    except requests.exceptions.Timeout:
        return {"found": False, "count": 0,
                "error": "Request timed out — breach check skipped"}
    except Exception as e:
        return {"found": False, "count": 0, "error": str(e)}
