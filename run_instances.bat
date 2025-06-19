@echo off
REM ───────────────────────────────────────────────────────────────────────
REM run_instances.bat
REM   Prompts for a count (if not given as %1) then launches that many
REM   cmd windows, each cd’d into your ECDH_Prototype folder and running
REM   ECDH_Prototype.py, and keeps them open.
REM ───────────────────────────────────────────────────────────────────────

set TARGET=C:\Users\User\ECDH_Prototype

REM If you passed a number as an argument, use it… otherwise ask
if "%~1"=="" (
  set /p COUNT="Enter number of windows to open: "
) else (
  set COUNT=%~1
)

REM Validate that COUNT is numeric
for /f "delims=0123456789" %%A in ("%COUNT%") do (
  echo Invalid number: %COUNT%
  pause
  exit /b 1
)

REM Launch COUNT copies
for /L %%i in (1,1,%COUNT%) do (
  start "ECDH Chat %%i" cmd.exe /K "cd /d "%TARGET%" && py ECDH_Prototype.py"
)
