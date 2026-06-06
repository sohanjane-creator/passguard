<div align="center">

# 🔐 PassGuard

**A secure, modern password manager & auditor built with Python**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/UI-Tkinter-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Mac%20%7C%20Linux-lightgrey?style=for-the-badge)

> Audit passwords · Generate strong passwords · Store credentials securely — all locally, no cloud.

</div>

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Password Auditor** | Score any password 0–100 with grade, entropy, crack time estimate |
| 💥 **Breach Check** | Live HaveIBeenPwned API check (k-anonymity, your password never leaves your machine) |
| ⚡ **Password Generator** | Random passwords or memorable passphrases with custom length & separators |
| 🗄️ **Encrypted Vault** | AES-128 Fernet encryption — master password never stored |
| 📜 **Password History** | Timestamped log of every credential save/update |
| 🔒 **Auto-Lock** | Vault locks automatically after 5 minutes of inactivity |
| 👁️ **Show/Hide Passwords** | Toggle password visibility in the vault table |
| ⏱️ **Clipboard Auto-Clear** | Copied passwords are wiped from clipboard after 30 seconds |
| 🌙 **Dark / Light Theme** | Switch themes instantly with one click |
| 🔄 **Vault Reset** | Secure two-step reset flow if master password is forgotten |

---

## 📸 Screenshots

> _Add your screenshots here after running the app_

| Audit | Vault | Generate |
|---|---|---|
| `screenshot_audit.png` | `screenshot_vault.png` | `screenshot_generate.png` |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/passguard.git
cd passguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python gui.py
```

---

## 🖥️ Build as a Standalone EXE (Windows)

Don't want to install Python? Build a one-click `.exe`:

```bash
# Double-click this file in the project folder:
build_fix.bat
```

Your app will appear at `dist\PassGuard.exe` — no Python required to run it.

---

## 📁 Project Structure

```
passguard/
├── gui.py            # Main Tkinter UI (entry point)
├── analyzer.py       # Password scoring engine
├── generator.py      # Password & passphrase generator
├── pwned.py          # HaveIBeenPwned API integration
├── vault.py          # Encrypted credential storage
├── main.py           # Original terminal UI (legacy)
├── requirements.txt  # Python dependencies
├── build_fix.bat     # Windows EXE build script
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

---

## 🔐 Security Notes

- **Master password is never stored** — it's used only to derive the encryption key
- **Vault uses Fernet (AES-128-CBC + HMAC-SHA256)** from the `cryptography` library
- **HIBP breach check uses k-anonymity** — only the first 5 chars of a SHA-1 hash are sent
- **Vault file** (`vault.db`) is stored locally — back it up yourself
- **Password history** is stored in `pw_history.json` — does NOT store actual passwords, only timestamps

---

## ⚙️ Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | Fernet encryption for vault |
| `requests` | HaveIBeenPwned API calls |
| `colorama` | Terminal color support (legacy CLI) |

Install all with:
```bash
pip install -r requirements.txt
```

---

## 🛠️ Configuration

| Setting | Default | Location |
|---|---|---|
| Auto-lock timeout | 5 minutes | `gui.py` → `AUTO_LOCK_SECONDS` |
| Clipboard clear delay | 30 seconds | `gui.py` → `CLIPBOARD_CLEAR_S` |
| Password history file | `pw_history.json` | `gui.py` → `HISTORY_FILE` |

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📋 Roadmap

- [ ] Password strength history graph
- [ ] Browser extension integration
- [ ] Cloud sync (optional, opt-in)
- [ ] Password categories / tags
- [ ] Two-factor authentication for vault
- [ ] Mobile companion app

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⭐ Support

If you find PassGuard useful, please consider giving it a **star ⭐** on GitHub!

---

<div align="center">
Made with ❤️ and Python
</div>
