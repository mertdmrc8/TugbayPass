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
echo Kasam.exe olusturuldu. Simdi Kasam.exe dosyasina cift tiklayabilirsiniz.
pause

