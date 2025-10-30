@echo off
rem Windows cmd build script for DecoderDetectorV2 (rich UI)
rem Requires: set BURP_JAR path, JDK on PATH.
rem NEED TO SET YOUR BURP JAR, JAR, and possibly JAVAC

setlocal EnableExtensions EnableDelayedExpansion

set "BURP_JAR=C:\Users\<YOUR_USERNAME>\AppData\Local\BurpSuitePro\burpsuite_pro.jar"
set "SRC_DIR=%~dp0src\main\java"
set "OUT_DIR=%~dp0classes"
set "OUT_JAR=%~dp0decoder-detector-v2.jar"
set "RELEASE=21"

where javac >nul 2>&1
if ERRORLEVEL 1 (
  echo [ERROR] javac not found in PATH.
  pause
  exit /b 1
)

if not exist "%BURP_JAR%" (
  echo [ERROR] BURP jar not found at: %BURP_JAR%
  echo Update the path at top of build.bat
  pause
  exit /b 1
)

if exist "%OUT_DIR%" rmdir /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"

echo [i] Compiling Java sources...
javac -cp "%BURP_JAR%" -d "%OUT_DIR%" "%SRC_DIR%\*.java" --release %RELEASE%
if ERRORLEVEL 1 (
  echo [ERROR] Compilation failed.
  pause
  exit /b 1
)

if exist "%OUT_JAR%" del "%OUT_JAR%"
echo [i] Creating jar with manifest...
"c:\Program Files\Java\jdk-25\bin\jar.exe" cfm "%OUT_JAR%" "%~dp0manifest.txt" -C "%OUT_DIR%" .
if ERRORLEVEL 1 (
  echo [ERROR] JAR creation failed.
  pause
  exit /b 1
)

echo [DONE] %OUT_JAR%
echo Load in Burp: Extender -> Add -> Java -> select the jar
pause
