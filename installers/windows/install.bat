@echo off
setlocal enabledelayedexpansion

REM LOCAL AI SCANNER - Windows Installer
REM Version 1.3

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

REM Get installation version from user
echo Available versions:
echo  [1] v1.3 Latest (Recommended)
echo  [2] v1.2
echo  [3] v1.1
echo  [4] v1.0
echo.
set /p VERSION="Select version (1-4, default is 1): "
if "%VERSION%"=="" set VERSION=1

if "%VERSION%"=="1" (
    set VERSION_NUM=1.3
    set RELEASE_DIR=1.3
) else if "%VERSION%"=="2" (
    set VERSION_NUM=1.2
    set RELEASE_DIR=1.2
) else if "%VERSION%"=="3" (
    set VERSION_NUM=1.1
    set RELEASE_DIR=1.1
) else if "%VERSION%"=="4" (
    set VERSION_NUM=1.0
    set RELEASE_DIR=1.0
) else (
    echo Invalid selection
    pause
    exit /b 1
)

REM Define installation paths
set INSTALL_ROOT=%ProgramFiles%\LocalAIScanner
set INSTALL_PATH=%INSTALL_ROOT%\v%VERSION_NUM%

echo.
echo Installation directory: %INSTALL_PATH%
echo.
set /p CONFIRM="Continue with installation? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo Installation cancelled
    exit /b 0
)

REM Create installation directories
echo.
echo Creating installation directories...
if not exist "%INSTALL_PATH%" (
    mkdir "%INSTALL_PATH%"
    if errorlevel 1 (
        echo Error: Failed to create installation directory
        pause
        exit /b 1
    )
)

REM Check for release archive
set RELEASE_PATH=%~dp0..\releases\windows
if not exist "%RELEASE_PATH%\%RELEASE_DIR%" (
    echo.
    echo Error: Release files not found at %RELEASE_PATH%\%RELEASE_DIR%
    echo Please ensure the release package is properly extracted
    pause
    exit /b 1
)

REM Copy files
echo Copying files...
xcopy "%RELEASE_PATH%\%RELEASE_DIR%\*" "%INSTALL_PATH%\" /E /I /Y >nul
if errorlevel 1 (
    echo Error: Failed to copy files
    pause
    exit /b 1
)

REM Find the actual executable name
set EXE_FILE=
if exist "%INSTALL_PATH%\LocalAIScanner.exe" (
    set EXE_FILE=%INSTALL_PATH%\LocalAIScanner.exe
)
if exist "%INSTALL_PATH%\main.exe" (
    set EXE_FILE=%INSTALL_PATH%\main.exe
)

if "!EXE_FILE!"=="" (
    echo Warning: Could not find executable file
    echo Files copied to: %INSTALL_PATH%
    echo Please ensure the release contains LocalAIScanner.exe or main.exe
    pause
    exit /b 0
)

REM Create batch file in Program Files for command-line access
echo Creating command-line wrapper...
(
    echo @echo off
    echo "!EXE_FILE!" %%*
) > "%INSTALL_ROOT%\LocalAIScanner.bat"

REM Add to PATH
echo Adding to system PATH...
setx PATH "%INSTALL_ROOT%;%PATH%" /M >nul
if errorlevel 1 (
    echo Warning: Could not modify system PATH
    echo Manual PATH adjustment may be required
)

REM Create desktop shortcut
echo Creating desktop shortcut...
set DESKTOP=%USERPROFILE%\Desktop

(
    echo [InternetShortcut]
    echo URL=file://!EXE_FILE!
) > "%DESKTOP%\LocalAIScanner.url"

REM Create Start Menu shortcut using PowerShell
powershell -Command "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::UTF8; $WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\LocalAIScanner.lnk'); $Shortcut.TargetPath = '!EXE_FILE!'; $Shortcut.WorkingDirectory = '%INSTALL_ROOT%'; $Shortcut.Description = 'LOCAL AI SCANNER v%VERSION_NUM%'; $Shortcut.Save()" 2>nul

REM Create uninstaller
echo Creating uninstaller...
(
    echo @echo off
    echo echo Removing LOCAL AI SCANNER v%VERSION_NUM%...
    echo rmdir /S /Q "%INSTALL_PATH%"
    echo if exist "%INSTALL_ROOT%" (
    echo   if not exist "%INSTALL_ROOT%\*" rmdir "%INSTALL_ROOT%"
    echo )
    echo echo Uninstallation complete
    echo pause
) > "%INSTALL_PATH%\uninstall.bat"

REM Test installation
echo.
echo Testing installation...
"!EXE_FILE!" --help >nul 2>&1
if errorlevel 1 (
    echo Warning: Executable test failed
    echo Installation may be incomplete
    echo Please verify the release package
) else (
    echo Installation verified successfully
)

echo.
echo =====================================================
echo   Installation Complete!
echo =====================================================
echo.
echo LOCAL AI SCANNER v%VERSION_NUM% installed to:
echo %INSTALL_PATH%
echo.
echo Usage:
echo  1. From Command Prompt:
echo     LocalAIScanner model.pkl
echo     LocalAIScanner C:\path\to\models
echo.
echo  2. From Desktop shortcut (double-click icon)
echo.
echo  3. Parameters:
echo     --scan-type {full,security,backdoor,format}
echo     -f, --output-format {text,json,csv,html}
echo     -o, --output-file FILE
echo     -v, --verbose
echo.
echo To uninstall: Run %INSTALL_PATH%\uninstall.bat
echo.
echo =====================================================
pause
endlocal
