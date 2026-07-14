@echo off
title Best Practices Doctor - Launcher
echo.
echo ========================================
echo   Best Practices Doctor
echo ========================================
echo.
echo Starting contributor mode with desktop, backend, and MCP...
echo.
npm run dev:full
echo.
echo Services stopped. Press any key to exit...
pause > nul
