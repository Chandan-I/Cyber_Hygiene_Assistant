@echo off
setlocal
title Cyber Hygiene Assistant Build Script

echo =====================================
echo   🚀 Building CyberHygieneAssistant.exe
echo =====================================

REM Define variables
set PROJECT_NAME=CyberHygieneAssistant
set DIST_DIR=dist
set BACKUP_DIR=backups

REM Create backups folder if not exists
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"

REM If previous EXE exists, back it up with timestamp
if exist "%DIST_DIR%\%PROJECT_NAME%.exe" (
    echo Backing up previous EXE...
    for /f "tokens=1-4 delims=/ " %%a in ('date /t') do set DATE=%%d-%%b-%%c
    for /f "tokens=1-2 delims=: " %%a in ('time /t') do set TIME=%%a%%b
    set TIME=%TIME: =0%
    set TIMESTAMP=%DATE%_%TIME%
    copy "%DIST_DIR%\%PROJECT_NAME%.exe" "%BACKUP_DIR%\%PROJECT_NAME%_%TIMESTAMP%.exe" >nul
    echo ✅ Backup saved as %BACKUP_DIR%\%PROJECT_NAME%_%TIMESTAMP%.exe
)

REM Clean old build folders
if exist build rmdir /s /q build
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
if exist "%PROJECT_NAME%.spec" del "%PROJECT_NAME%.spec"

REM Build fresh EXE
echo 🔨 Building new version...
python -m PyInstaller --onefile --noconsole --uac-admin --icon=app_icon.ico --add-data "manual.html;." --add-data "quiz.json;." --name "%PROJECT_NAME%" main.py

echo =====================================
echo ✅ Build Complete!
echo Your EXE is in: %DIST_DIR%\%PROJECT_NAME%.exe
echo Backup Folder:  %BACKUP_DIR%
echo =====================================
pause
endlocal
