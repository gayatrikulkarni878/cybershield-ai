@echo off
title CyberShield AI - Hackathon Launcher
color 0A

echo ===================================================
echo               CYBERSHIELD AI 
echo   "Your Intelligent Shield Against Digital Threats"
echo ===================================================
echo.
echo Starting CyberShield AI Backend and Frontend...
echo.

:: Launch Backend in separate window
start "CyberShield AI Backend (FastAPI)" cmd /k "cd backend && python -m uvicorn main:app --reload --port 8000"

:: Launch Frontend in separate window using corepack pnpm / npm
start "CyberShield AI Frontend (Vite)" cmd /k "cd frontend && corepack pnpm dev --open || npm run dev --open"

echo.
echo Both services are launching!
echo Backend API: http://localhost:8000
echo Frontend UI: http://localhost:5173
echo.
echo Press any key to exit this launcher window...
pause >nul
