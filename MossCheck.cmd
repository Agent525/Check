@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: Check for Administrator Privileges
:: ============================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit
)

:: ============================================================================
:: Get target directory from user
:: ============================================================================
:get_path
cls
set "targetPath="
set /p "targetPath=Enter the full path to the directory you want to scan: "

if not defined targetPath (
    echo No path entered. Please try again.
    timeout /t 2 >nul
    goto :get_path
)

if not exist "%targetPath%" (
    echo Path not found: "%targetPath%"
    echo Please try again.
    timeout /t 2 >nul
    goto :get_path
)

cd /d "%targetPath%"

:: ============================================================================
:: List files in the current directory and let the user choose
:: ============================================================================
:select_file
cls
echo ==================================================
echo  Select a file to inspect:
echo ==================================================
echo.

set "count=0"
for %%F in (*) do (
    if /i not "%%~nxF"=="%~nx0" (
        set /a count+=1
        set "file[!count!]=%%~fF"
        echo [!count!] %%~nxF
    )
)

if %count% equ 0 (
    echo No other files found in this directory.
    pause
    exit
)

echo.
echo ==================================================
echo.
set /p "file_choice=Enter the number of the file to check: "

if %file_choice% gtr 0 if %file_choice% leq %count% (
    set "filePath=!file[%file_choice%]!"
) else (
    echo Invalid selection. Please try again.
    timeout /t 2 >nul
    goto :select_file
)

:menu
cls
echo ==================================================
echo  File Operations for:
echo  %filePath%
echo ==================================================
echo.
echo  [1] Check Hash (SHA256)
echo  [2] Check File Details
echo  [3] Select another file
echo  [4] Exit
echo.
echo ==================================================
echo.

set /p "choice=Enter your choice (1-4): "

if "%choice%"=="1" goto :check_hash
if "%choice%"=="2" goto :check_details
if "%choice%"=="3" goto :select_file
if "%choice%"=="4" goto :eof

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto :menu

:check_hash
cls
echo ==================================================
echo  Calculating SHA256 Hash
echo ==================================================
echo.
certutil -hashfile "%filePath%" SHA256
echo.
echo ==================================================
pause
goto :menu

:check_details
cls
echo ==================================================
echo  File Details
echo ==================================================
echo.
set "wmicPath=%filePath:\=\\%"
wmic datafile where "name='%wmicPath%'" get /format:list
echo.
echo ==================================================
pause
goto :menu

endlocal
