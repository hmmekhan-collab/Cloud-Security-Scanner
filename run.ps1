# CSA Startup Script
# Usage: Right-click → Run with PowerShell  (or: .\run.ps1 in terminal)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Cloud Security Analyzer (CSA) - Starting..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

Set-Location $PSScriptRoot
python app.py
