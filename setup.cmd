@echo off
title Best Practices Doctor - Setup
cd /d "%~dp0"
echo.
echo ========================================
echo   Best Practices Doctor Setup
echo ========================================
echo.
npm run setup
echo.
echo Setup finished. Press any key to exit...
pause > nul
