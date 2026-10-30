@echo off
cd /d "%~dp0"
set /p ADMIN_PASSWORD=<admin-parol.txt
start "" http://127.0.0.1:3000/admin
node server.js
