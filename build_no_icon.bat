@echo off
echo ============================================
echo   PassGuard - Build EXE (no icon needed)
echo ============================================
echo.

echo [1/3] Installing PyInstaller...
pip install pyinstaller --quiet

echo [2/3] Building PassGuard.exe...
pyinstaller ^
  --onefile ^
  --windowed ^
  --name "PassGuard" ^
  --add-data "analyzer.py;." ^
  --add-data "pwned.py;." ^
  --add-data "generator.py;." ^
  --add-data "vault.py;." ^
  --hidden-import cryptography ^
  --hidden-import requests ^
  --hidden-import colorama ^
  gui.py

echo.
echo [3/3] Done!
echo Your EXE is at:  dist\PassGuard.exe
echo.
pause
