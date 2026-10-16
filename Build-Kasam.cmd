@echo off
setlocal
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo Windows .NET Framework derleyicisi bulunamadi.
  pause
  exit /b 1
)
"%CSC%" /nologo /target:winexe /out:"%~dp0Kasam.exe" /win32icon:"%~dp0Kasam.ico" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll "%~dp0Kasam.cs"
if errorlevel 1 (
  echo Kasam.exe olusturulamadi.
  pause
  exit /b 1
)
"%CSC%" /nologo /target:winexe /out:"%~dp0TugbayPass-Setup-1.3.4.exe" /win32icon:"%~dp0Kasam.ico" /resource:"%~dp0Kasam.exe",Kasam.exe /resource:"%~dp0Kasam.ico",Kasam.ico /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "%~dp0Setup.cs"
if errorlevel 1 (
  echo Kurulum dosyasi olusturulamadi.
  pause
  exit /b 1
)
if not exist "%~dp0dist" mkdir "%~dp0dist"
copy /y "%~dp0TugbayPass-Setup-1.3.4.exe" "%~dp0dist\TugbayPass-Setup-1.3.4.exe" >nul
copy /y "%~dp0update.json" "%~dp0dist\update.json" >nul
echo TugbayPass v1.3.4 uygulamasi ve secilebilir kurulum konumuna sahip setup olusturuldu.
pause
