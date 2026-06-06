"""
generator.py — Secure Password Generator
Uses Python's secrets module (cryptographically secure RNG)
to generate passwords and passphrases.
"""

import secrets
import string


# A curated word list for passphrases (subset for demo — expand for production)
WORD_LIST = [
    "apple", "bridge", "castle", "delta", "engine", "forest",
    "garden", "harbor", "island", "jungle", "kernel", "lemon",
    "mango", "nebula", "ocean", "planet", "quartz", "rocket",
    "silver", "tiger", "umbrella", "valley", "winter", "xenon",
    "yellow", "zenith", "anchor", "beacon", "circuit", "dragon",
    "ember", "falcon", "glacier", "horizon", "iris", "jasper",
    "knight", "lantern", "marble", "nexus", "orbit", "pillar",
    "quarry", "raven", "storm", "thunder", "ultra", "vortex",
    "walnut", "xylem", "yonder", "zephyr", "blaze", "cobalt"
]


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length (min 8)
        use_uppercase: Include A-Z
        use_digits: Include 0-9
        use_special: Include !@#$%^&* etc.
        exclude_ambiguous: Exclude l, 1, O, 0, I (look-alike chars)
    """
    length = max(8, length)

    charset = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]

    if use_uppercase:
        charset += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        charset += string.digits
        required.append(secrets.choice(string.digits))
    if use_special:
        special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        charset += special_chars
        required.append(secrets.choice(special_chars))

    if exclude_ambiguous:
        ambiguous = set("l1O0I")
        charset = "".join(c for c in charset if c not in ambiguous)

    # Fill the rest randomly
    remaining_length = length - len(required)
    password_chars = required + [secrets.choice(charset) for _ in range(remaining_length)]

    # Shuffle to avoid predictable positions for required chars
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def generate_passphrase(word_count: int = 4, separator: str = "-",
                        capitalize: bool = True, add_number: bool = True) -> str:
    """
    Generate a memorable passphrase (e.g. 'Rocket-Forest-Zenith-42').
    Passphrases are both strong and memorable — often better than random strings.

    Args:
        word_count: Number of words (min 3)
        separator: Character between words
        capitalize: Capitalize first letter of each word
        add_number: Append a random 2-digit number
    """
    word_count = max(3, word_count)
    words = [secrets.choice(WORD_LIST) for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    passphrase = separator.join(words)

    if add_number:
        passphrase += separator + str(secrets.randbelow(90) + 10)

    return passphrase


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Estimate how long a password would take to crack
    assuming 10 billion guesses/second (modern GPU cluster).
    """
    guesses_per_second = 10_000_000_000  # 10 billion
    total_guesses = 2 ** entropy_bits
    seconds = total_guesses / guesses_per_second

    if seconds < 1:
        return "less than a second"
    elif seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 3153600000:
        return f"{seconds/31536000:.1f} years"
    else:
        return f"{seconds/31536000:.2e} years (practically uncrackable)"
