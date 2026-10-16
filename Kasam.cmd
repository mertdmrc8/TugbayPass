@echo off
setlocal
if not exist "%~dp0Kasam.exe" call "%~dp0Build-Kasam.cmd"
if exist "%~dp0Kasam.exe" start "" "%~dp0Kasam.exe"

