@echo off
echo ============================================
echo   PassGuard - Fixed Build
echo ============================================
echo.

:: Clean old build junk first
echo [1/4] Cleaning old build files...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist PassGuard.spec del PassGuard.spec

:: Upgrade pip + reinstall dependencies cleanly
echo [2/4] Reinstalling dependencies cleanly...
python -m pip install --upgrade pip --quiet
pip install --upgrade pyinstaller cryptography requests colorama --quiet

:: Build with extra compatibility flags
echo [3/4] Building PassGuard.exe...
pyinstaller ^
  --onefile ^
  --windowed ^
  --name "PassGuard" ^
  --add-data "analyzer.py;." ^
  --add-data "pwned.py;." ^
  --add-data "generator.py;." ^
  --add-data "vault.py;." ^
  --hidden-import cryptography ^
  --hidden-import cryptography.hazmat.primitives ^
  --hidden-import cryptography.hazmat.backends ^
  --hidden-import cryptography.hazmat.backends.openssl ^
  --hidden-import cryptography.fernet ^
  --hidden-import requests ^
  --hidden-import colorama ^
  --collect-all cryptography ^
  --noupx ^
  gui.py

echo.
echo [4/4] Build complete!
echo.
echo EXE location:  dist\PassGuard.exe
echo.
pause
