@echo off
title Best Practices Doctor - Launcher
echo.
echo ========================================
echo   Best Practices Doctor
echo ========================================
echo.
echo Starting all services with automatic configuration...
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0run-all.ps1" -NoWatch -BackendPort 50401
echo.
echo Services stopped. Press any key to exit...
pause > nul
