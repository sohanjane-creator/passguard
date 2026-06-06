"""
main.py — Password Auditor & Manager
Entry point with interactive terminal UI.

Install dependencies first:
    pip install cryptography requests colorama

Run:
    python main.py
"""

import sys
import getpass
import os

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _NoColor()

from analyzer import score_password
from pwned import check_pwned
from generator import generate_password, generate_passphrase, estimate_crack_time
from vault import (
    vault_exists, create_vault, unlock_vault,
    add_credential, get_all_credentials, search_credentials,
    delete_credential, get_vault_stats
)


# ── UI Helpers ──────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}🔐  Password Auditor & Manager  v1.0{Fore.CYAN}        ║
║  {Fore.YELLOW}Secure • Private • Open Source{Fore.CYAN}               ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def section(title: str):
    print(f"\n{Fore.CYAN}{'─' * 48}")
    print(f"  {Fore.WHITE}{title}")
    print(f"{Fore.CYAN}{'─' * 48}{Style.RESET_ALL}")

def success(msg): print(f"{Fore.GREEN}  ✔  {msg}{Style.RESET_ALL}")
def error(msg):   print(f"{Fore.RED}  ✘  {msg}{Style.RESET_ALL}")
def warn(msg):    print(f"{Fore.YELLOW}  ⚠  {msg}{Style.RESET_ALL}")
def info(msg):    print(f"{Fore.CYAN}  ℹ  {msg}{Style.RESET_ALL}")

def prompt(msg: str, secret: bool = False) -> str:
    if secret:
        return getpass.getpass(f"  {Fore.YELLOW}▶  {msg}: {Style.RESET_ALL}")
    return input(f"  {Fore.YELLOW}▶  {msg}: {Style.RESET_ALL}").strip()

def pause():
    input(f"\n  {Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


# ── Grade Coloring ──────────────────────────────────────────────────────────

def grade_color(grade: str) -> str:
    colors = {"A+": Fore.GREEN, "A": Fore.GREEN, "B": Fore.YELLOW,
              "C": Fore.YELLOW, "D": Fore.RED, "F": Fore.RED}
    return colors.get(grade, Fore.WHITE)


# ── Feature: Audit a Password ───────────────────────────────────────────────

def feature_audit():
    section("Audit a Password")
    password = prompt("Enter password to audit", secret=True)
    if not password:
        error("No password entered.")
        return

    print(f"\n{Fore.WHITE}  Analyzing...{Style.RESET_ALL}")

    # Strength analysis
    result = score_password(password)
    grade = result["grade"]
    score = result["score"]
    gc = grade_color(grade)

    print(f"\n  {'Score:':<20} {gc}{score}/100  [{grade}]{Style.RESET_ALL}")
    print(f"  {'Entropy:':<20} {result['entropy']} bits")
    print(f"  {'Crack time est.:':<20} {estimate_crack_time(result['entropy'])}")

    print(f"\n{Fore.CYAN}  Score Breakdown:{Style.RESET_ALL}")
    for k, v in result["breakdown"].items():
        print(f"    {k:<22} {v}")

    if result["issues"]:
        print(f"\n{Fore.RED}  Weaknesses Found:{Style.RESET_ALL}")
        for issue in result["issues"]:
            print(f"    {Fore.RED}✘{Style.RESET_ALL}  {issue}")

    if result["suggestions"]:
        print(f"\n{Fore.YELLOW}  Suggestions:{Style.RESET_ALL}")
        for suggestion in result["suggestions"]:
            print(f"    {Fore.YELLOW}→{Style.RESET_ALL}  {suggestion}")

    # Breach check
    print(f"\n{Fore.WHITE}  Checking HaveIBeenPwned database...{Style.RESET_ALL}")
    pwned = check_pwned(password)
    if pwned["error"]:
        warn(f"Breach check skipped: {pwned['error']}")
    elif pwned["found"]:
        error(f"EXPOSED IN DATA BREACHES! Found {pwned['count']:,} times.")
        error("Change this password immediately — it's in attacker dictionaries.")
    else:
        success("Not found in any known data breaches.")

    pause()


# ── Feature: Generate a Password ────────────────────────────────────────────

def feature_generate():
    section("Generate a Secure Password")

    print(f"\n  {Fore.WHITE}Generation Mode:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}1{Style.RESET_ALL}  Random Password (high entropy)")
    print(f"    {Fore.CYAN}2{Style.RESET_ALL}  Passphrase (memorable words)")

    choice = prompt("Choose mode (1/2)", )
    generated = None

    if choice == "2":
        try:
            word_count = int(prompt("Number of words (default: 4)") or "4")
        except ValueError:
            word_count = 4
        sep = prompt("Separator (default: -)") or "-"
        generated = generate_passphrase(word_count=word_count, separator=sep)
    else:
        try:
            length = int(prompt("Password length (default: 20)") or "20")
        except ValueError:
            length = 20
        no_special = prompt("Include special chars? (Y/n)").lower()
        use_special = no_special != "n"
        generated = generate_password(length=length, use_special=use_special)

    if generated:
        result = score_password(generated)
        gc = grade_color(result["grade"])

        print(f"\n  {Fore.WHITE}Generated:{Style.RESET_ALL}")
        print(f"\n    {Fore.GREEN}{generated}{Style.RESET_ALL}\n")
        print(f"  Score: {gc}{result['score']}/100 [{result['grade']}]{Style.RESET_ALL}")
        print(f"  Entropy: {result['entropy']} bits")
        print(f"  Crack time: {estimate_crack_time(result['entropy'])}")

    pause()


# ── Feature: Vault — Add Entry ───────────────────────────────────────────────

def feature_vault_add(fernet):
    section("Add Credential to Vault")
    site = prompt("Site/App name (e.g. gmail.com)")
    username = prompt("Username / Email")

    print(f"\n  {Fore.WHITE}Password options:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}1{Style.RESET_ALL}  Enter my own password")
    print(f"    {Fore.CYAN}2{Style.RESET_ALL}  Generate one now")
    choice = prompt("Choice (1/2)")

    if choice == "2":
        password = generate_password(length=20)
        result = score_password(password)
        gc = grade_color(result["grade"])
        print(f"\n  Generated: {Fore.GREEN}{password}{Style.RESET_ALL}")
        print(f"  Score: {gc}{result['score']}/100 [{result['grade']}]{Style.RESET_ALL}")
    else:
        password = prompt("Password", secret=True)
        if password:
            result = score_password(password)
            gc = grade_color(result["grade"])
            print(f"  Strength: {gc}{result['score']}/100 [{result['grade']}]{Style.RESET_ALL}")

    notes = prompt("Notes (optional, press Enter to skip)")

    if not site or not username or not password:
        error("Site, username, and password are all required.")
        return

    if add_credential(fernet, site, username, password, notes):
        success(f"Saved '{site}' to vault.")
    else:
        error("Failed to save credential.")

    pause()


# ── Feature: Vault — View All ────────────────────────────────────────────────

def feature_vault_view(fernet):
    section("All Stored Credentials")
    creds = get_all_credentials(fernet)

    if not creds:
        warn("Your vault is empty. Add some credentials first!")
        pause()
        return

    for cred in creds:
        print(f"\n  {Fore.CYAN}[{cred['id']}]{Style.RESET_ALL}  {Fore.WHITE}{cred['site']}{Style.RESET_ALL}")
        print(f"       User:     {cred['username']}")
        print(f"       Password: {Fore.GREEN}{cred['password']}{Style.RESET_ALL}")
        if cred["notes"]:
            print(f"       Notes:    {cred['notes']}")
        print(f"       Saved:    {cred['created_at']}")

    pause()


# ── Feature: Vault — Search ──────────────────────────────────────────────────

def feature_vault_search(fernet):
    section("Search Vault")
    query = prompt("Search for site")
    if not query:
        return

    results = search_credentials(fernet, query)
    if not results:
        warn(f"No results found for '{query}'")
    else:
        print(f"\n  {Fore.GREEN}Found {len(results)} result(s):{Style.RESET_ALL}")
        for cred in results:
            print(f"\n  {Fore.CYAN}[{cred['id']}]{Style.RESET_ALL}  {Fore.WHITE}{cred['site']}{Style.RESET_ALL}")
            print(f"       User:     {cred['username']}")
            print(f"       Password: {Fore.GREEN}{cred['password']}{Style.RESET_ALL}")

    pause()


# ── Feature: Vault — Delete ──────────────────────────────────────────────────

def feature_vault_delete(fernet):
    section("Delete a Credential")
    creds = get_all_credentials(fernet)
    if not creds:
        warn("Your vault is empty.")
        pause()
        return

    for cred in creds:
        print(f"  {Fore.CYAN}[{cred['id']}]{Style.RESET_ALL}  {cred['site']} — {cred['username']}")

    try:
        cred_id = int(prompt("Enter ID to delete (0 to cancel)"))
    except ValueError:
        error("Invalid ID.")
        return

    if cred_id == 0:
        return

    confirm = prompt(f"Type 'yes' to confirm deletion of ID {cred_id}")
    if confirm.lower() == "yes":
        if delete_credential(cred_id):
            success("Credential deleted.")
        else:
            error("No credential found with that ID.")
    else:
        info("Deletion cancelled.")

    pause()


# ── Feature: Vault Stats ─────────────────────────────────────────────────────

def feature_vault_stats():
    section("Vault Statistics")
    stats = get_vault_stats()
    print(f"\n  Total passwords stored: {Fore.WHITE}{stats['total_passwords']}{Style.RESET_ALL}")
    print(f"  Unique sites:           {Fore.WHITE}{stats['unique_sites']}{Style.RESET_ALL}")
    if stats["oldest"]:
        print(f"  Oldest entry:           {stats['oldest']}")
        print(f"  Newest entry:           {stats['newest']}")
    pause()


# ── Vault Menu ───────────────────────────────────────────────────────────────

def vault_menu(fernet):
    while True:
        clear()
        banner()
        section("Password Vault")
        stats = get_vault_stats()
        info(f"Vault unlocked — {stats['total_passwords']} password(s) stored")

        print(f"""
  {Fore.CYAN}1{Style.RESET_ALL}  Add new credential
  {Fore.CYAN}2{Style.RESET_ALL}  View all credentials
  {Fore.CYAN}3{Style.RESET_ALL}  Search credentials
  {Fore.CYAN}4{Style.RESET_ALL}  Delete a credential
  {Fore.CYAN}5{Style.RESET_ALL}  Vault stats
  {Fore.CYAN}0{Style.RESET_ALL}  Back to main menu
""")
        choice = prompt("Choose an option")

        if choice == "1":   feature_vault_add(fernet)
        elif choice == "2": feature_vault_view(fernet)
        elif choice == "3": feature_vault_search(fernet)
        elif choice == "4": feature_vault_delete(fernet)
        elif choice == "5": feature_vault_stats()
        elif choice == "0": break
        else: error("Invalid option.")


# ── Vault Login/Setup ────────────────────────────────────────────────────────

def open_vault():
    section("Password Vault")

    if not vault_exists():
        warn("No vault found. Let's create one.")
        print(f"\n  {Fore.WHITE}Your master password encrypts all stored passwords.")
        print(f"  It is NEVER stored — if you forget it, data cannot be recovered.{Style.RESET_ALL}\n")

        pw1 = prompt("Create master password", secret=True)
        pw2 = prompt("Confirm master password", secret=True)

        if pw1 != pw2:
            error("Passwords don't match.")
            return
        if len(pw1) < 8:
            error("Master password must be at least 8 characters.")
            return

        strength = score_password(pw1)
        if strength["score"] < 50:
            warn(f"Master password is weak (score: {strength['score']}/100). Consider making it stronger.")
            confirm = prompt("Continue anyway? (yes/no)")
            if confirm.lower() != "yes":
                return

        print(f"\n  {Fore.WHITE}Creating vault...{Style.RESET_ALL}")
        create_vault(pw1)
        success("Vault created successfully!")
        fernet = unlock_vault(pw1)
    else:
        master_pw = prompt("Enter master password", secret=True)
        print(f"\n  {Fore.WHITE}Unlocking...{Style.RESET_ALL}")
        fernet = unlock_vault(master_pw)
        if fernet is None:
            error("Wrong master password.")
            return

    success("Vault unlocked!")
    vault_menu(fernet)


# ── Main Menu ────────────────────────────────────────────────────────────────

def main():
    while True:
        clear()
        banner()
        print(f"""  {Fore.WHITE}What would you like to do?{Style.RESET_ALL}

  {Fore.CYAN}1{Style.RESET_ALL}  Audit a password
  {Fore.CYAN}2{Style.RESET_ALL}  Generate a secure password
  {Fore.CYAN}3{Style.RESET_ALL}  Open password vault
  {Fore.CYAN}0{Style.RESET_ALL}  Exit
""")
        choice = prompt("Choose an option")

        if choice == "1":   feature_audit()
        elif choice == "2": feature_generate()
        elif choice == "3": open_vault()
        elif choice == "0":
            print(f"\n  {Fore.CYAN}Stay secure! 🔐{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            error("Invalid option. Try again.")


if __name__ == "__main__":
    main()
