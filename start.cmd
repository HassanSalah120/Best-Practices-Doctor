@echo off
title Best Practices Doctor
cd /d "%~dp0"
echo.
echo ========================================
echo   Best Practices Doctor
echo ========================================
echo.
echo Starting from repository root...
echo.
npm start
echo.
echo Best Practices Doctor stopped. Press any key to exit...
pause > nul
