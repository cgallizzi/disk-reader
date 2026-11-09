@echo off
rem Builds dist\CardViewer.exe, a single portable file. Build tools stay in .venv.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe py -3.12 -m venv .venv || exit /b 1
.venv\Scripts\python -m pip install --quiet --disable-pip-version-check pyinstaller || exit /b 1
.venv\Scripts\python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name CardViewer card_viewer.py || exit /b 1
echo Built %~dp0dist\CardViewer.exe
