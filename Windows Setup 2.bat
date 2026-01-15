rem Delete Windows Recovery Partition / Extend Windows Partition
rem start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Macrorit\mde-free-portable\x64\dm.exe"

rem pause

"C:\Program Files (x86)\Creative\Sound Blaster Command\Creative.SBCommand.exe"

pause

rem Set 165 Hz
rem Disable Sound Devices
rem Network Connection - all adapters - Uncheck all but IPv4

control

pause

rem reg add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f

regedit

pause

rem Uninstall all but VBScript required by AMD Chipset Software
start ms-settings:optionalfeatures

pause

rem rd "Z:\Brave" /s /q
taskkill /im brave.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" /r /d y
xcopy "D:\OneDrive\Soft\Brave" "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" /s /i /y
rem rd "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" /s /q
rem mklink /d "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" "Z:\Brave"

rem rd "Z:\Chromium" /s /q
taskkill /im chrome.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\Chromium\User Data" /r /d y
xcopy "D:\OneDrive\Soft\Chromium" "%LocalAppData%\Chromium\User Data" /s /i /y
rem rd "%LocalAppData%\Chromium\User Data" /s /q
rem mklink /d "%LocalAppData%\Chromium\User Data" "Z:\Chromium"

rem rd "Z:\Edge" /s /q
taskkill /im msedge.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\Microsoft\Edge" /r /d y
xcopy "D:\OneDrive\Soft\Edge" "%LocalAppData%\Microsoft\Edge" /s /i /y
rem rd "%LocalAppData%\Microsoft\Edge" /s /q
rem mklink /d "%LocalAppData%\Microsoft\Edge" "Z:\Edge"

rem rd "Z:\librewolf" /s /q
taskkill /im librewolf.exe /f
takeown /s %computername% /u %username% /f "%AppData%\Librewolf" /r /d y
xcopy "D:\OneDrive\Soft\Librewolf" "%AppData%\Librewolf" /s /i /y
rem rd "%AppData%\Librewolf" /s /q
rem mklink /d "%AppData%\Librewolf" "Z:\Librewolf"

pause

start "" /wait "D:\OneDrive\Setup\Setup.exe"
start "" /wait "D:\OneDrive\Setup\0.reg"
taskkill /im explorer.exe /f & explorer.exe
xcopy "C:\Setup" "%USERPROFILE%\Desktop" /s /i /y
rd "C:\Setup" /s /q

pause

start "" /wait "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"

pause

start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\NanaZip.lnk"

pause

rem https://support.brave.com/hc/en-us/articles/360044860011-How-Do-I-Use-Command-Line-Flags-in-Brave-
rem https://github.com/dreammjow/ChromiumHardening/blob/main/flags/chrome-command-line.md
rem https://get.webgl.org / https://www.cloudflare.com/ssl/encrypted-sni / https://pq.cloudflareresearch.com
rem "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --enable-features="EnableCsrssLockdown,EncryptedClientHello,IsolatePrerenders,IsolateSandboxedIframes,RendererAppContainer,WinSboxDisableExtensionPoint" --disable-webgl --no-pings

rem Disabled
rem edge://flags/#allow-all-sites-to-initiate-mirroring
rem edge://flags/#edge-compose
rem edge://flags/#edge-copilot-mode
rem edge://flags/#edge-copilot-mode-profile-toggle
rem edge://flags/#edge-copilot-vision
rem edge://flags/#edge-llm-on-device-model-performance-param
rem edge://flags/#edge-ntp-composer-allow-copilot-search
rem edge://flags/#edge-ntp-composer-feed-integration
rem edge://flags/#edge-omnibox-commercial-copilot-chat
rem edge://flags/#edge-omnibox-ui-hide-steady-state-url-scheme
rem edge://flags/#edge-omnibox-ui-hide-steady-state-url-trivial-subdomains
rem edge://flags/#edge-optin-experimentation
rem edge://flags/#edge-rounded-containers
rem edge://flags/#edge-visual-rejuv-mica
rem edge://flags/#enable-force-dark
rem edge://flags/#enable-quic
rem edge://flags/#enable-windows-gaming-input-data-fetcher
rem edge://flags/#media-router-cast-allow-all-ips
rem edge://flags/#prefetch-new-tab-page-trigger
rem edge://flags/#ui-disable-partial-swap

rem Enabled
rem edge://flags/#disallow-doc-written-script-loads
rem edge://flags/#enable-standard-device-bound-session-credentials
rem edge://flags/#enable-tls13-early-data
rem edge://flags/#local-network-access-check
rem edge://flags/#origin-keyed-processes-by-default
rem edge://flags/#strict-origin-isolation

pause

reg add "HKLM\Software\TruckersMP" /v "InstallDir" /t REG_SZ /d "C:\Program Files\TruckersMP Launcher" /f
reg add "HKLM\Software\TruckersMP" /v "InstallLocationETS2" /t REG_SZ /d "D:\Steam\steamapps\common\Euro Truck Simulator 2" /f
start "" /wait "D:\Steam\steam.exe"
start "" /wait "D:\OneDrive\Setup\TruckersMP-Setup.exe"

rem Steam Interface - Disable Everything

pause

rem AMD Controller Emulation
pnputil /disable-device "ROOT\AMDXE\0000"

rem AMD Crash Defender
pnputil /disable-device "ROOT\AMDLOG\0000"

rem AMD High Definition Audio Device
pnputil /disable-device "HDAUDIO\FUNC_01&VEN_1002&DEV_AA01&SUBSYS_00AA0100&REV_1008\5&1CD0132C&0&0001"

rem AMD High Definition Audio Device
pnputil /disable-device "HDAUDIO\FUNC_01&VEN_1002&DEV_AA01&SUBSYS_00AA0100&REV_1008\7&ADEDD0B&0&0001"

rem AMD PSP 11.0 Device
pnputil /disable-device "PCI\VEN_1022&DEV_15C7&SUBSYS_15C71022&REV_00\4&98C338A&0&0241"

rem AMD Radeon 760M Graphics
pnputil /disable-device "PCI\VEN_1002&DEV_15BF&SUBSYS_35BF1849&REV_05\4&98C338A&0&0041"

rem AMD SMBUS
pnputil /disable-device "PCI\VEN_1022&DEV_790B&SUBSYS_790B1849&REV_71\3&11583659&0&A0"

rem AMD Streaming Audio Device
pnputil /disable-device "ROOT\AMDSAFD&FUN_01&REV_01\0000"

rem Composite Bus Enumerator
pnputil /disable-device "ROOT\COMPOSITEBUS\0000"

rem Microsoft GS Wavetable Synth
pnputil /disable-device "SWD\MMDEVAPI\MICROSOFTGSWAVETABLESYNTH"

rem Microsoft Hyper-V Virtualization Infrastructure Driver
pnputil /disable-device "ROOT\VID\0000"

rem Microsoft Kernel Debug Network Adapter
pnputil /disable-device "ROOT\KDNIC\0000"

rem NDIS Virtual Network Adapter Enumerator
pnputil /disable-device "ROOT\NDISVIRTUALBUS\0000"

rem NPU Compute Accelerator Device
pnputil /disable-device "PCI\VEN_1022&DEV_1502&SUBSYS_15021022&REV_00\4&92D7D1B&0&0142"

rem Remote Desktop Device Redirector Bus
pnputil /disable-device "ROOT\RDPBUS\0000"

rem Standard SATA AHCI Controller
pnputil /disable-device "PCI\VEN_1022&DEV_43F6&SUBSYS_10621B21&REV_01\6&6318A00&0&00680011"

rem System speaker
pnputil /disable-device "ACPI\PNP0800\4&D447ADA&0"

rem UMBus Root Bus Enumerator
pnputil /disable-device "ROOT\UMBUS\0000"

rem Update Drivers!
rem Enable - Disk Drives - XPG Policies

devmgmt.msc

pause

start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\TCPOptimizer.exe"

rem Restart Now !

pause

rem Restart NOW !!!

pause

rem Anti-ransomware prevention, E: is read only (for backup) Administrator rights are required to modify, SYSTEM is blocked
rem https://medium.com/tenable-techblog/bypass-windows-10-user-group-policy-and-more-with-this-one-weird-trick-552d4bc5cc1b
rem This means if we set an explicit entry to “DENY” SYSTEM writable permissions, then it will effectively block “SYSTEM” from obtaining writable permissions since our “DENY” rule will take precedence over the “ALLOW” rule that it tries to add.
rem takeown /s %computername% /u %username% /f E: /r /d y
rem icacls E: /inheritance:r
rem icacls E: /grant:r %username%:(OI)(CI)F /t /l /q /c
rem icacls E: /grant "Users":(OI)(CI)RX /t /l /q /c
rem icacls E: /deny "System":(OI)(CI)F /t /l /q /c


rem ============================ Manual Config Required / Optional =============================


rem Apply Windows Tweaks at will / <(^.^)>
rem Windows Cleanup - https://github.com/TairikuOokami/Windows/blob/main/Windows%20Cleanup.bat
rem Windows Defender Disable - https://github.com/TairikuOokami/Windows/blob/main/Microsoft%20Defender%20Disable.bat
rem Windows Tweaks - https://github.com/TairikuOokami/Windows/blob/main/Windows%20Tweaks.bat

rem Make Sure Secure Boot is ON after BIOS Update !!!!!
rem Disable CPU Performance Killers Modes: NX, PSS, SMT

rem Take Ownership of the Registry key and give permissions to Admin - https://www.youtube.com/watch?v=M1l5ifYKefg
rem To remove Network from Explorer/allow cleaning WebCache
rem "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder"
rem "HKCR\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}"
rem "HKCR\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}"
rem ________________________________________________________________________________________
rem "HKCR\Wow6432Node\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}"
rem "HKCR\Wow6432Node\AppID\{0358b920-0ac7-461f-98f4-58e32cd89148}"
rem "HKLM\Software\Wow6432Node\Classes\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}"
rem "HKLM\Software\Wow6432Node\Classes\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}"
