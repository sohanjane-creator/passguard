@echo off
echo ============================================
echo   PassGuard - Build EXE
echo ============================================
echo.

:: Step 1 - Install PyInstaller
echo [1/3] Installing PyInstaller...
pip install pyinstaller --quiet

:: Step 2 - Build the exe
echo [2/3] Building PassGuard.exe...
pyinstaller ^
  --onefile ^
  --windowed ^
  --name "PassGuard" ^
  --icon "icon.ico" ^
  --add-data "analyzer.py;." ^
  --add-data "pwned.py;." ^
  --add-data "generator.py;." ^
  --add-data "vault.py;." ^
  --hidden-import cryptography ^
  --hidden-import requests ^
  --hidden-import colorama ^
  gui.py

:: Step 3 - Done
echo.
echo [3/3] Done!
echo.
echo Your EXE is at:  dist\PassGuard.exe
echo Double-click it to launch PassGuard!
echo.
pause
