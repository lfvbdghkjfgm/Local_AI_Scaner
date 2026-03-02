@echo off
setlocal enabledelayedexpansion

REM LOCAL AI SCANNER - Windows Installer
REM Supports pre-built executables or installation from source with venv

echo.
echo =====================================================
echo   LOCAL AI SCANNER - Installation Wizard
echo =====================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Administrator privileges required
    echo Please run this installer as Administrator
    echo.
    pause
    exit /b 1
)

REM Resolve project root relative to this script location
set "SCRIPT_DIR=%~dp0"
for %%A in ("%SCRIPT_DIR%..\..") do set "BASE_DIR=%%~fA"

REM Get installation version from user
:VERSION_LOOP
echo.
echo Available versions:
echo  [1] v1.3 Latest (Recommended)
echo  [2] v1.2
echo  [3] v1.1
echo  [4] v1.0
echo.
set /p VERSION_CHOICE="Select version (1-4, default is 1): "
if "!VERSION_CHOICE!"=="" set VERSION_CHOICE=1

if "!VERSION_CHOICE!"=="1" (
    set VERSION_NUM=1.3
    set RELEASE_DIR=1.3
) else if "!VERSION_CHOICE!"=="2" (
    set VERSION_NUM=1.2
    set RELEASE_DIR=1.2
) else if "!VERSION_CHOICE!"=="3" (
    set VERSION_NUM=1.1
    set RELEASE_DIR=1.1
) else if "!VERSION_CHOICE!"=="4" (
    set VERSION_NUM=1.0
    set RELEASE_DIR=1.0
) else (
    echo.
    echo Invalid selection. Please enter 1, 2, 3, or 4.
    goto VERSION_LOOP
)

REM Choose installation method
:METHOD_LOOP
echo.
echo Installation method:
echo  [1] Pre-built executable (Recommended - fast)
echo  [2] From source with venv (Requires Python)
echo.
set /p INSTALL_METHOD="Select method (1-2, default is 1): "
if "!INSTALL_METHOD!"=="" set INSTALL_METHOD=1

if "!INSTALL_METHOD!"=="1" (
    set METHOD=RELEASE
) else if "!INSTALL_METHOD!"=="2" (
    set METHOD=SOURCE
) else (
    echo.
    echo Invalid selection. Please enter 1 or 2.
    goto METHOD_LOOP
)

REM Define installation paths
set INSTALL_ROOT=%ProgramFiles%\LocalAIScanner
set INSTALL_PATH=!INSTALL_ROOT!\v!VERSION_NUM!

echo.
echo Installation details:
echo  Version: v!VERSION_NUM!
echo  Method: !METHOD!
echo  Location: !INSTALL_PATH!
echo.
set /p CONFIRM="Continue? (Y/N): "

if /i "!CONFIRM!"=="n" (
    echo Installation cancelled
    pause
    exit /b 0
)
if /i "!CONFIRM!"=="no" (
    echo Installation cancelled
    pause
    exit /b 0
)

REM Create installation directory
echo.
echo Creating installation directories...
if not exist "!INSTALL_PATH!" (
    mkdir "!INSTALL_PATH!"
    if errorlevel 1 (
        echo Error: Failed to create installation directory
        pause
        exit /b 1
    )
)

REM Installation from pre-built release
if "!METHOD!"=="RELEASE" (
    echo.
    echo Installing from pre-built release...
    
    set "RELEASE_PATH=!BASE_DIR!\releases\!RELEASE_DIR!\windows"
    
    if not exist "!RELEASE_PATH!" (
        echo.
        echo Error: Release files not found at:
        echo !RELEASE_PATH!
        echo.
        echo Please ensure:
        echo - The releases folder exists in the installation package
        echo - Windows builds are located at releases\VERSION\windows\
        echo.
        pause
        exit /b 1
    )
    
    set "ARCHIVE_FILE="
    for %%F in ("!RELEASE_PATH!\*.zip" "!RELEASE_PATH!\*.rar") do (
        if not defined ARCHIVE_FILE if exist "%%~fF" set "ARCHIVE_FILE=%%~fF"
    )

    if defined ARCHIVE_FILE (
        echo Extracting release archive...
        tar -xf "!ARCHIVE_FILE!" -C "!INSTALL_PATH!"
        if errorlevel 1 (
            echo Error: Failed to extract archive:
            echo !ARCHIVE_FILE!
            echo Ensure Windows tar is available and archive is not corrupted
            pause
            exit /b 1
        )
    ) else (
        echo Copying executable files...
        xcopy "!RELEASE_PATH!\*" "!INSTALL_PATH!\" /E /I /Y >nul
        if errorlevel 1 (
            echo Error: Failed to copy files
            pause
            exit /b 1
        )
    )
    
    REM Find and create shortcut for executable
    set EXE_FILE=
    if exist "!INSTALL_PATH!\LocalAIScanner.exe" (
        set EXE_FILE=!INSTALL_PATH!\LocalAIScanner.exe
    ) else if exist "!INSTALL_PATH!\main.exe" (
        set EXE_FILE=!INSTALL_PATH!\main.exe
    )
    
    if defined EXE_FILE (
        echo Creating start menu shortcut...
        call :CREATE_SHORTCUT "!EXE_FILE!" "!INSTALL_PATH!"
    )
)

REM Installation from source with venv
if "!METHOD!"=="SOURCE" (
    echo.
    echo Installing from source with Python virtual environment...
    
    REM Check if Python is installed
    python --version >nul 2>&1
    if errorlevel 1 (
        echo.
        echo Error: Python is not installed or not in PATH
        echo Please install Python 3.8 or higher from python.org
        echo.
        pause
        exit /b 1
    )
    
    echo Python found. Creating virtual environment...
    
    REM Create virtual environment
    python -m venv "!INSTALL_PATH!\venv"
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
    
    REM Activate venv and install dependencies
    echo Activating virtual environment and installing dependencies...
    
    set VENV_ACTIVATE=!INSTALL_PATH!\venv\Scripts\activate.bat
    
    REM Copy source files
    set "SRC_PATH=!BASE_DIR!\src\!RELEASE_DIR!"
    
    if not exist "!SRC_PATH!" (
        echo.
        echo Error: Source files not found at:
        echo !SRC_PATH!
        echo.
        pause
        exit /b 1
    )
    
    echo Copying source files...
    xcopy "!SRC_PATH!\*" "!INSTALL_PATH!\source\" /E /I /Y >nul
    if errorlevel 1 (
        echo Error: Failed to copy source files
        pause
        exit /b 1
    )
    
    REM Install requirements
    echo Installing Python dependencies...
    set "REQUIREMENTS_PATH=!BASE_DIR!\requirements.txt"
    
    if exist "!REQUIREMENTS_PATH!" (
        call "!VENV_ACTIVATE!"
        pip install -q -r "!REQUIREMENTS_PATH!"
        if errorlevel 1 (
            echo Warning: Some dependencies failed to install
            echo You may need to install them manually
        )
    ) else (
        echo Warning: requirements.txt not found, skipping pip install
        echo You may need to install dependencies manually
    )
    
    REM Create batch file to run the app
    (
        echo @echo off
        echo cd /d "!INSTALL_PATH!\source"
        echo call "!VENV_ACTIVATE!"
        echo python main.py %%*
    ) > "!INSTALL_PATH!\LocalAIScanner.bat"
    
    echo Creating start menu shortcut...
    call :CREATE_SHORTCUT "!INSTALL_PATH!\LocalAIScanner.bat" "!INSTALL_PATH!\source"
)

echo.
echo Creating uninstaller...
call :WRITE_UNINSTALLER "!INSTALL_PATH!"
if errorlevel 1 (
    echo Warning: Failed to create uninstaller
)

REM Add to PATH (optional, for convenience)
echo.
set /p ADD_PATH="Add installation directory to system PATH? (Y/N): "
if /i "!ADD_PATH!"=="y" (
    echo Adding to PATH...
    setx PATH "!INSTALL_PATH!;%%PATH%%"
    echo Successfully added to PATH
)
if /i "!ADD_PATH!"=="yes" (
    echo Adding to PATH...
    setx PATH "!INSTALL_PATH!;%%PATH%%"
    echo Successfully added to PATH
)

echo.
echo =====================================================
echo   Installation Complete!
echo =====================================================
echo.
echo Version: v!VERSION_NUM!
echo Location: !INSTALL_PATH!
if "!METHOD!"=="SOURCE" (
    echo Method: From source with venv
    echo Run: LocalAIScanner.bat [options] PATH
) else (
    echo Method: Pre-built executable
    if defined EXE_FILE (
        echo Run: !EXE_FILE! [options] PATH
    ) else (
        echo Executable not found - check installation folder
    )
)
echo.
echo Usage examples:
echo   LocalAIScanner model.pkl
echo   LocalAIScanner ./models -f json -o results.json
echo.
echo For help, run: LocalAIScanner --help
echo To uninstall, run: "!INSTALL_PATH!\uninstall.bat"
echo.
pause
exit /b 0

:WRITE_UNINSTALLER
set "UNINSTALL_DIR=%~1"
if not exist "%UNINSTALL_DIR%" exit /b 1
(
    echo @echo off
    echo setlocal
    echo set "TARGET_DIR=%%~dp0"
    echo if "%%TARGET_DIR:~-1%%"=="\" set "TARGET_DIR=%%TARGET_DIR:~0,-1%%"
    echo echo.
    echo echo ================================================
    echo echo   LOCAL AI SCANNER - Uninstaller
    echo echo ================================================
    echo echo.
    echo echo Target: %%TARGET_DIR%%
    echo echo.
    echo set /p CONFIRM="Continue uninstall? ^(Y/N^): "
    echo if /i not "%%CONFIRM%%"=="y" if /i not "%%CONFIRM%%"=="yes" ^(
    echo   echo Uninstall cancelled
    echo   pause
    echo   exit /b 0
    echo ^)
    echo net session ^>nul 2^>^&1
    echo if %%errorlevel%% neq 0 ^(
    echo   echo Error: Administrator privileges required
    echo   echo Please run uninstall.bat as Administrator
    echo   pause
    echo   exit /b 1
    echo ^)
    echo set "SHORTCUT_USER=%%AppData%%\Microsoft\Windows\Start Menu\Programs\LocalAIScanner.lnk"
    echo set "SHORTCUT_ALL=%%ProgramData%%\Microsoft\Windows\Start Menu\Programs\LocalAIScanner.lnk"
    echo if exist "%%SHORTCUT_USER%%" del /f /q "%%SHORTCUT_USER%%" ^>nul 2^>^&1
    echo if exist "%%SHORTCUT_ALL%%" del /f /q "%%SHORTCUT_ALL%%" ^>nul 2^>^&1
    echo echo Removing files...
    echo set "SELF_PATH=%%~f0"
    echo set "TMP_CMD=%%TEMP%%\las_uninstall_%%RANDOM%%.cmd"
    echo ^> "%%TMP_CMD%%" echo @echo off
    echo ^>^> "%%TMP_CMD%%" echo timeout /t 2 /nobreak ^^^^>nul
    echo ^>^> "%%TMP_CMD%%" echo rmdir /s /q "%%TARGET_DIR%%"
    echo ^>^> "%%TMP_CMD%%" echo del /f /q "%%SELF_PATH%%" ^^^^>nul 2^^^^>^^^^^&1
    echo ^>^> "%%TMP_CMD%%" echo del /f /q "%%~f0" ^^^^>nul 2^^^^>^^^^^&1
    echo start "" cmd /c "%%TMP_CMD%%"
    echo echo Uninstallation started.
    echo echo This window can be closed.
    echo exit /b 0
) > "%UNINSTALL_DIR%\uninstall.bat"
exit /b 0

:CREATE_SHORTCUT
set "SHORTCUT_TARGET=%~1"
set "SHORTCUT_WORKDIR=%~2"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$WshShell = New-Object -ComObject WScript.Shell; $StartMenuPath = [System.Environment]::GetFolderPath('StartMenu'); $ShortcutPath = Join-Path $StartMenuPath 'Programs\LocalAIScanner.lnk'; $Shortcut = $WshShell.CreateShortcut($ShortcutPath); $Shortcut.TargetPath = '%SHORTCUT_TARGET%'; $Shortcut.WorkingDirectory = '%SHORTCUT_WORKDIR%'; $Shortcut.Description = 'Local AI Scanner - ML Model Security Analysis'; $Shortcut.Save()"
if errorlevel 1 (
    echo Warning: Failed to create start menu shortcut
)
exit /b 0
