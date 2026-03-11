@echo off
setlocal enabledelayedexpansion

REM LOCAL AI SCANNER - Windows Installer
REM Supports pre-built executables or installation from source with venv
REM Downloads required files from internet (no local repository needed)

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

set "DEFAULT_REPO_ZIP_URL=https://github.com/lfvbdghkjfgm/Local_AI_Scaner/archive/refs/heads/main.zip"
set "REPO_ZIP_URL=%DEFAULT_REPO_ZIP_URL%"
if not "%LAS_REPO_ZIP_URL%"=="" set "REPO_ZIP_URL=%LAS_REPO_ZIP_URL%"
set "REMOTE_TMP_DIR="
set "REMOTE_ZIP="
set "REMOTE_BASE_DIR="

REM Get installation version from user
:VERSION_LOOP
echo.
echo Available versions:
echo  [1] v1.5.1 Latest (Recommended)
echo  [2] v1.5
echo  [3] v1.4
echo  [4] v1.3
echo  [5] v1.2
echo  [6] v1.1
echo  [7] v1.0
echo.
set /p VERSION_CHOICE="Select version (1-7, default is 1): "
if "!VERSION_CHOICE!"=="" set VERSION_CHOICE=1

if "!VERSION_CHOICE!"=="1" (
    set VERSION_NUM=1.5.1
    set RELEASE_DIR=1.5.1
) else if "!VERSION_CHOICE!"=="2" (
    set VERSION_NUM=1.5
    set RELEASE_DIR=1.5
) else if "!VERSION_CHOICE!"=="3" (
    set VERSION_NUM=1.4
    set RELEASE_DIR=1.4
) else if "!VERSION_CHOICE!"=="4" (
    set VERSION_NUM=1.3
    set RELEASE_DIR=1.3
) else if "!VERSION_CHOICE!"=="5" (
    set VERSION_NUM=1.2
    set RELEASE_DIR=1.2
) else if "!VERSION_CHOICE!"=="6" (
    set VERSION_NUM=1.1
    set RELEASE_DIR=1.1
) else if "!VERSION_CHOICE!"=="7" (
    set VERSION_NUM=1.0
    set RELEASE_DIR=1.0
) else (
    echo.
    echo Invalid selection. Please enter 1, 2, 3, 4, 5, 6, or 7.
    goto VERSION_LOOP
)

REM Choose installation method
:METHOD_LOOP
echo.
echo Installation method:
echo  [1] Pre-built executable (fast)
echo  [2] From source with venv (Recommended)
echo.
set /p INSTALL_METHOD="Select method (1-2, default is 2): "
if "!INSTALL_METHOD!"=="" set INSTALL_METHOD=2

if "!INSTALL_METHOD!"=="1" (
    set METHOD=RELEASE
) else if "!INSTALL_METHOD!"=="2" (
    set METHOD=SOURCE
) else (
    echo.
    echo Invalid selection. Please enter 1 or 2.
    goto METHOD_LOOP
)

REM Choose operation mode
:OPERATION_LOOP
echo.
echo Operation mode:
echo  [1] Install new or reinstall
echo  [2] Update existing installation (same version)
echo.
set /p OPERATION_CHOICE="Select mode (1-2, default is 1): "
if "!OPERATION_CHOICE!"=="" set OPERATION_CHOICE=1

if "!OPERATION_CHOICE!"=="1" (
    set OPERATION=INSTALL
) else if "!OPERATION_CHOICE!"=="2" (
    set OPERATION=UPDATE
) else (
    echo.
    echo Invalid selection. Please enter 1 or 2.
    goto OPERATION_LOOP
)

REM Define installation paths
set INSTALL_ROOT=%ProgramFiles%\LocalAIScanner
set INSTALL_PATH=!INSTALL_ROOT!\v!VERSION_NUM!
set COMMAND_NAME=local-ai-scanner
set COMMAND_ALIAS=las
set COMMAND_ALT=local-ai-scaner
set COMMAND_PATH=!INSTALL_PATH!\!COMMAND_NAME!.bat
set ALIAS_PATH=!INSTALL_PATH!\!COMMAND_ALIAS!.bat
set ALT_PATH=!INSTALL_PATH!\!COMMAND_ALT!.bat
set RUN_TARGET=

echo.
echo Installation details:
echo  Version: v!VERSION_NUM!
echo  Method: !METHOD!
echo  Operation: !OPERATION!
echo  Location: !INSTALL_PATH!

if "!OPERATION!"=="UPDATE" (
    if not exist "!INSTALL_PATH!" (
        echo.
        echo Error: Existing installation not found for update:
        echo !INSTALL_PATH!
        echo.
        echo Install this version first or choose operation mode [1].
        pause
        exit /b 1
    )
)

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

echo.
echo Downloading required files from internet...
echo Source URL: !REPO_ZIP_URL!
call :FETCH_REMOTE_REPO
if errorlevel 1 (
    echo Error: Failed to download and prepare installation sources.
    echo You can override the URL with environment variable LAS_REPO_ZIP_URL.
    call :CLEANUP_REMOTE
    pause
    exit /b 1
)
set "BASE_DIR=!REMOTE_BASE_DIR!"
echo Using downloaded package: !BASE_DIR!

REM Create installation directory
echo.
echo Creating installation directories...
if "!OPERATION!"=="UPDATE" (
    echo Existing installation detected. Replacing files...
    rmdir /s /q "!INSTALL_PATH!" >nul 2>&1
    if exist "!INSTALL_PATH!" (
        echo Error: Failed to clean existing installation directory
        pause
        exit /b 1
    )
)
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
        echo - The selected version has release files at releases\VERSION\windows\
        echo - Or choose method [2] From source with venv
        echo - Or override URL with LAS_REPO_ZIP_URL
        echo.
        call :CLEANUP_REMOTE
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
        set RUN_TARGET=!EXE_FILE!
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
    
    REM Install dependencies into the created venv
    echo Preparing dependency installation...
    
    REM Copy source files
    set "SRC_PATH=!BASE_DIR!\src\!RELEASE_DIR!"
    
    if not exist "!SRC_PATH!" (
        echo.
        echo Error: Source files not found at:
        echo !SRC_PATH!
        echo.
        echo You can override source URL with LAS_REPO_ZIP_URL.
        call :CLEANUP_REMOTE
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
        echo.
        echo Installing Python dependencies. Progress shown below...
        "!INSTALL_PATH!\venv\Scripts\python.exe" -m pip install --progress-bar on -r "!REQUIREMENTS_PATH!"
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
        echo setlocal
        echo set "SRC_DIR=!INSTALL_PATH!\source"
        echo set "PY_EXE=!INSTALL_PATH!\venv\Scripts\python.exe"
        echo if not exist "%%PY_EXE%%" ^(
        echo   echo Error: Python runtime not found: %%PY_EXE%%
        echo   endlocal ^& exit /b 1
        echo ^)
        echo if not exist "%%SRC_DIR%%\main.py" ^(
        echo   echo Error: main.py not found in %%SRC_DIR%%
        echo   endlocal ^& exit /b 1
        echo ^)
        echo set "LAS_INVOKE_CWD=%%CD%%"
        echo "%%PY_EXE%%" "%%SRC_DIR%%\main.py" %%*
        echo set "EXIT_CODE=%%ERRORLEVEL%%"
        echo endlocal ^& exit /b %%EXIT_CODE%%
    ) > "!INSTALL_PATH!\LocalAIScanner.bat"

    set RUN_TARGET=!INSTALL_PATH!\LocalAIScanner.bat
    
    echo Creating start menu shortcut...
    call :CREATE_SHORTCUT "!INSTALL_PATH!\LocalAIScanner.bat" "!INSTALL_PATH!\source"
)

echo.
echo Creating global command launcher: !COMMAND_NAME!
if not defined RUN_TARGET (
    echo Error: Cannot create launcher because target command is not defined
    pause
    exit /b 1
)

(
    echo @echo off
    echo set "TARGET=!RUN_TARGET!"
    echo if not exist "%%TARGET%%" ^(
    echo   echo Error: Installed target not found: %%TARGET%%
    echo   exit /b 1
    echo ^)
    echo call "%%TARGET%%" %%*
    echo exit /b %%ERRORLEVEL%%
) > "!COMMAND_PATH!"

if errorlevel 1 (
    echo Error: Failed to create command launcher at:
    echo !COMMAND_PATH!
    pause
    exit /b 1
)

(
    echo @echo off
    echo call "!COMMAND_PATH!" %%*
    echo exit /b %%ERRORLEVEL%%
) > "!ALIAS_PATH!"

if errorlevel 1 (
    echo Error: Failed to create alias launcher at:
    echo !ALIAS_PATH!
    pause
    exit /b 1
)

(
    echo @echo off
    echo call "!COMMAND_PATH!" %%*
    echo exit /b %%ERRORLEVEL%%
) > "!ALT_PATH!"

if errorlevel 1 (
    echo Error: Failed to create alternate launcher at:
    echo !ALT_PATH!
    pause
    exit /b 1
)

echo Ensuring !INSTALL_PATH! is in system PATH...
call :ADD_TO_SYSTEM_PATH "!INSTALL_PATH!"
if errorlevel 1 (
    echo Warning: Failed to update system PATH automatically
    echo You can add this path manually:
    echo !INSTALL_PATH!
) else (
    set "PATH=!INSTALL_PATH!;!PATH!"
    echo PATH updated. You may need to open a new terminal.
)

echo.
echo Creating uninstaller...
call :WRITE_UNINSTALLER "!INSTALL_PATH!"
if errorlevel 1 (
    echo Warning: Failed to create uninstaller
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
    echo Run: !COMMAND_NAME! or !COMMAND_ALIAS! [options] PATH
) else (
    echo Method: Pre-built executable
    if defined EXE_FILE (
        echo Run: !COMMAND_NAME! or !COMMAND_ALIAS! [options] PATH
    ) else (
        echo Executable not found - check installation folder
    )
)
echo.
echo Usage examples:
echo   !COMMAND_NAME! model.pkl
echo   !COMMAND_NAME! ./models -f json -o results.json
echo   !COMMAND_ALIAS! ./models --scan-type security
echo.
echo For help, run: !COMMAND_NAME! --help
echo Also available as: !COMMAND_ALIAS! and !COMMAND_ALT!
echo Launcher path: !COMMAND_PATH!
echo To uninstall, run: "!INSTALL_PATH!\uninstall.bat"
echo.
call :CLEANUP_REMOTE
pause
exit /b 0

:FETCH_REMOTE_REPO
set "REMOTE_TMP_DIR=%TEMP%\las_repo_%RANDOM%_%RANDOM%"
set "REMOTE_ZIP=%TEMP%\las_repo_%RANDOM%_%RANDOM%.zip"
if exist "!REMOTE_TMP_DIR!" rmdir /s /q "!REMOTE_TMP_DIR!" >nul 2>&1
if exist "!REMOTE_ZIP!" del /f /q "!REMOTE_ZIP!" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "Invoke-WebRequest -Uri '!REPO_ZIP_URL!' -OutFile '!REMOTE_ZIP!';" ^
  "Expand-Archive -Path '!REMOTE_ZIP!' -DestinationPath '!REMOTE_TMP_DIR!' -Force"
if errorlevel 1 exit /b 1
set "REMOTE_BASE_DIR="
for /d %%D in ("!REMOTE_TMP_DIR!\*") do (
    if not defined REMOTE_BASE_DIR set "REMOTE_BASE_DIR=%%~fD"
)
if not defined REMOTE_BASE_DIR exit /b 1
if not exist "!REMOTE_BASE_DIR!\src" exit /b 1
if not exist "!REMOTE_BASE_DIR!\requirements.txt" exit /b 1
exit /b 0

:CLEANUP_REMOTE
if defined REMOTE_ZIP if exist "!REMOTE_ZIP!" del /f /q "!REMOTE_ZIP!" >nul 2>&1
if defined REMOTE_TMP_DIR if exist "!REMOTE_TMP_DIR!" rmdir /s /q "!REMOTE_TMP_DIR!" >nul 2>&1
exit /b 0

:ADD_TO_SYSTEM_PATH
set "PATH_ENTRY=%~1"
if "%PATH_ENTRY%"=="" exit /b 1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$entry = '%PATH_ENTRY%';" ^
  "$existing = [Environment]::GetEnvironmentVariable('Path', 'Machine');" ^
  "if (-not $existing) { $existing = '' };" ^
  "$items = $existing -split ';' | Where-Object { $_ -and ($_ -ne $entry) };" ^
  "$updated = ((@($entry) + $items) -join ';');" ^
  "[Environment]::SetEnvironmentVariable('Path', $updated, 'Machine');"
if errorlevel 1 exit /b 1
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
    echo set /p CONFIRM="Continue uninstall? (Y/N): "
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
    echo powershell -NoProfile -ExecutionPolicy Bypass -Command "$target='%%TARGET_DIR%%'; $existing=[Environment]::GetEnvironmentVariable('Path','Machine'); if($existing){ $items=@(); foreach($p in ($existing -split ';')){ if($p -and ($p -ne $target)){ $items += $p } }; [Environment]::SetEnvironmentVariable('Path', ($items -join ';'), 'Machine') }"
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
