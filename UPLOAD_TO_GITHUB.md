# How to Upload PassGuard to GitHub

## Step 1 — Create the repo on GitHub
1. Go to github.com → click **"New repository"**
2. Name it: `passguard`
3. Description: `🔐 A secure local password manager & auditor built with Python + Tkinter`
4. Set to **Public**
5. ❌ Do NOT add README, .gitignore, or license (we have our own)
6. Click **"Create repository"**

---

## Step 2 — Open CMD in your project folder
Right-click your `password_manager` folder → **"Open in Terminal"** or:
```cmd
cd C:\Users\TEST\Desktop\password_manager
```

---

## Step 3 — Run these commands one by one

```cmd
git init
git add .
git commit -m "🔐 Initial release - PassGuard v1.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/passguard.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your actual GitHub username.

---

## Step 4 — Update README with your username
Open `README.md` and replace:
```
YOUR_USERNAME
```
with your actual GitHub username in the clone URL.

---

## Files that will be uploaded ✅
- gui.py
- main.py
- analyzer.py
- generator.py
- pwned.py
- vault.py
- requirements.txt
- README.md
- LICENSE
- .gitignore
- build_fix.bat

## Files that will be IGNORED 🔒 (sensitive - protected by .gitignore)
- vault.db (your encrypted passwords)
- pw_history.json (your history)
- dist/ (built exe)
- build/ (build artifacts)
