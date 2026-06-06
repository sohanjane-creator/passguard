"""
vault.py — Encrypted Password Vault
Stores credentials in a local SQLite DB, encrypted with AES-128
using the Fernet symmetric encryption scheme (from the cryptography library).
The master password is never stored — only a PBKDF2-derived key hash for verification.
"""

import os
import sqlite3
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


DB_FILE = "vault.db"
PBKDF2_ITERATIONS = 480_000  # NIST 2023 recommendation


# ── Key Derivation ──────────────────────────────────────────────────────────

def _derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from the master password + salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def _get_connection():
    return sqlite3.connect(DB_FILE)


# ── Vault Initialization ────────────────────────────────────────────────────

def vault_exists() -> bool:
    """Check if a vault has been created."""
    if not os.path.exists(DB_FILE):
        return False
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='meta'")
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def create_vault(master_password: str) -> bool:
    """
    Create a new vault. Stores a random salt and a verification hash
    (SHA-256 of the derived key) so we can verify the master password later.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password_enc TEXT NOT NULL,
            notes_enc TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    salt = os.urandom(32)
    derived_key = _derive_key(master_password, salt)
    # Store a hash of the derived key for verification (not the key itself)
    key_hash = hashlib.sha256(derived_key).hexdigest()

    cursor.execute("INSERT OR REPLACE INTO meta VALUES ('salt', ?)",
                   (base64.b64encode(salt).decode(),))
    cursor.execute("INSERT OR REPLACE INTO meta VALUES ('key_hash', ?)", (key_hash,))

    conn.commit()
    conn.close()
    return True


def unlock_vault(master_password: str):
    """
    Verify master password and return a Fernet instance if correct.
    Returns None if password is wrong.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT value FROM meta WHERE key='salt'")
    salt = base64.b64decode(cursor.fetchone()[0])

    cursor.execute("SELECT value FROM meta WHERE key='key_hash'")
    stored_hash = cursor.fetchone()[0]

    conn.close()

    derived_key = _derive_key(master_password, salt)
    if hashlib.sha256(derived_key).hexdigest() != stored_hash:
        return None  # Wrong password

    return Fernet(derived_key)


# ── CRUD Operations ─────────────────────────────────────────────────────────

def add_credential(fernet: Fernet, site: str, username: str,
                   password: str, notes: str = "") -> bool:
    """Encrypt and store a credential entry."""
    enc_password = fernet.encrypt(password.encode()).decode()
    enc_notes = fernet.encrypt(notes.encode()).decode() if notes else ""

    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO credentials (site, username, password_enc, notes_enc) VALUES (?,?,?,?)",
        (site, username, enc_password, enc_notes)
    )
    conn.commit()
    conn.close()
    return True


def get_all_credentials(fernet: Fernet) -> list:
    """Retrieve and decrypt all stored credentials."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, site, username, password_enc, notes_enc, created_at FROM credentials ORDER BY site"
    )
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        try:
            decrypted_pw = fernet.decrypt(row[3].encode()).decode()
            decrypted_notes = fernet.decrypt(row[4].encode()).decode() if row[4] else ""
            results.append({
                "id": row[0],
                "site": row[1],
                "username": row[2],
                "password": decrypted_pw,
                "notes": decrypted_notes,
                "created_at": row[5]
            })
        except InvalidToken:
            results.append({"id": row[0], "site": row[1],
                            "username": row[2], "password": "[DECRYPTION ERROR]",
                            "notes": "", "created_at": row[5]})
    return results


def search_credentials(fernet: Fernet, query: str) -> list:
    """Search credentials by site name."""
    all_creds = get_all_credentials(fernet)
    return [c for c in all_creds if query.lower() in c["site"].lower()]


def delete_credential(credential_id: int) -> bool:
    """Delete a credential by its ID."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_vault_stats() -> dict:
    """Return basic vault statistics."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM credentials")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT site) FROM credentials")
    unique_sites = cursor.fetchone()[0]
    cursor.execute("SELECT MIN(created_at), MAX(created_at) FROM credentials")
    dates = cursor.fetchone()
    conn.close()
    return {
        "total_passwords": total,
        "unique_sites": unique_sites,
        "oldest": dates[0],
        "newest": dates[1]
    }
