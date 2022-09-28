rem Delete Windows Recovery Partition / Extend Windows Partition
start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Macrorit\mde-free-portable\x64\dm.exe"

pause

rem Disable Indexing C:/Z:
explorer

pause

start "" /wait "D:\OneDrive\Setup\SBZSeriesDriverInstaller.exe"

pause

"C:\Program Files (x86)\Creative\Sound Blaster Command\Creative.SBCommand.exe"

pause

rem Set 75 Hz
rem Disable Sound Devices
rem Network Connection - all adapters - Uncheck all but IPv4

control

pause

rem Uninstall all but WMIC
start ms-settings:optionalfeatures

pause

rd "Z:\Brave" /s /q
taskkill /im brave.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" /r /d y
xcopy "D:\OneDrive\Soft\Brave" "Z:\Brave" /s /i /y
rd "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" /s /q
mklink /d "%LocalAppData%\BraveSoftware\Brave-Browser\User Data" "Z:\Brave"

rd "Z:\Edge" /s /q
taskkill /im msedge.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\Microsoft\Edge" /r /d y
xcopy "D:\OneDrive\Soft\Edge" "Z:\Edge" /s /i /y
rd "%LocalAppData%\Microsoft\Edge" /s /q
mklink /d "%LocalAppData%\Microsoft\Edge" "Z:\Edge"

rd "Z:\librewolf" /s /q
taskkill /im librewolf.exe /f
takeown /s %computername% /u %username% /f "%AppData%\Librewolf" /r /d y
xcopy "D:\OneDrive\Soft\Librewolf" "Z:\Librewolf" /s /i /y
rd "%AppData%\Librewolf" /s /q
mklink /d "%AppData%\Librewolf" "Z:\Librewolf"

pause

start "" /wait "D:\OneDrive\Setup\Setup.exe"
start "" /wait "D:\OneDrive\Setup\0.reg"
taskkill /im explorer.exe /f & explorer.exe
xcopy "C:\Setup" "Z:\Desktop" /s /i /y
rd "C:\Setup" /s /q

pause

start "" /wait "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"

pause

start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\NanaZip.lnk"
start "" "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\2fast - two factor authenticator supporting TOTP.lnk"

pause

rem https://github.com/dreammjow/ChromiumHardening/blob/main/flags/chrome-command-line.md
rem https://peter.sh/experiments/chromium-command-line-switches
rem https://get.webgl.org / https://defo.ie/ech-check.php
rem "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --disable-webgl --enable-features="EnableCsrssLockdown,EncryptedClientHello,GpuAppContainer,IsolateSandboxedIframes,RendererAppContainer" --no-pings

rem Disabled #edge-omnibox-ui-hide-steady-state-url-scheme
rem Disabled #edge-omnibox-ui-hide-steady-state-url-trivial-subdomains
rem Disabled #edge-share-menu
rem Disabled #edge-show-feature-recommendations
rem Disabled #enable-quic
rem Disabled #edge-prenav
rem Enabled #block-insecure-private-network-requests
rem Enabled #disallow-doc-written-script-loads
rem Enabled #dns-https-svcb
rem Enabled #edge-automatic-https
rem Enabled #edge-autoplay-user-setting-block-option
rem Enabled #edge-overlay-scrollbars-win-style
rem Enabled #edge-visual-rejuv-materials-menu
rem Enabled #edge-visual-rejuv-show-settings
rem Enabled #partitioned-cookies
rem Enabled #strict-origin-isolation
rem edge://flags

rem Search engine used in the address bar
start "" "https://neeva.com"
rem edge://settings/search

pause

reg add "HKLM\Software\TruckersMP" /v "InstallDir" /t REG_SZ /d "C:\Program Files\TruckersMP Launcher" /f
reg add "HKLM\Software\TruckersMP" /v "InstallLocationETS2" /t REG_SZ /d "D:\Steam\steamapps\common\Euro Truck Simulator 2" /f
start "" /wait "D:\Steam\steam.exe"
start "" /wait "D:\OneDrive\Setup\Install TruckersMP.exe"

pause

rem Update Drivers!
rem Enable - Disk Drives - XPG Policies
rem Enable - Hidden devices
rem Disable Audio Inputs - All not used
rem Disable IDE ATA - All not used
rem Disable Network Adapters - All not used
rem Disable Ports - All not used
rem Disable Security Devices - AMD PSP
rem Disable Software Devices - All not used
rem Disable Sound - AMD HDAD, AMD Streaming
rem Disable System Devices - AMD Crash Defender, AMD Link, AMD SMBus, Composite Bus Enumerator, MS Hyper-V, MS Virtual Drive, NDIS Virtual, Remote Desktop, System Speaker, UMBus
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

rem Selection Search eyJzZWFyY2hFbmdpbmVzIjpbeyJuYW1lIjoiSU1EYiIsInVybCI6Imh0dHBzOi8vd3d3LmltZGIuY29tL2ZpbmQ/cz1hbGwmcT0lcyJ9LHsibmFtZSI6IlNvZnRwZWRpYSIsInVybCI6Imh0dHBzOi8vd2luLnNvZnRwZWRpYS5jb20vZHluLXNlYXJjaC5waHA/c2VhcmNoX3Rlcm09JXMifSx7Im5hbWUiOiJEaWN0aW9uYXJ5IiwidXJsIjoiaHR0cHM6Ly93d3cubWVycmlhbS13ZWJzdGVyLmNvbS9kaWN0aW9uYXJ5LyVzIn0seyJuYW1lIjoiMTIzTW92aWVzIiwidXJsIjoiaHR0cHM6Ly93dzUuMDEyM21vdmllLm5ldC9zZWFyY2guaHRtbD9xPSVzIn0seyJuYW1lIjoiUHV0bG9ja2VyIiwidXJsIjoiaHR0cHM6Ly9wdXRsb2NrZXIuZ3kvc2VhcmNoLyVzIn0seyJuYW1lIjoibTR1ZnJlZSIsInVybCI6Imh0dHBzOi8vbTR1ZnJlZS50by9zZWFyY2gvJXMuaHRtbCJ9LHsibmFtZSI6Ik15QW5pbWUiLCJ1cmwiOiJodHRwczovL215YW5pbWVsaXN0Lm5ldC9hbmltZS5waHA/cT0lcyZjYXQ9YW5pbWUifSx7Im5hbWUiOiJBbmlXYXRjaGVyIiwidXJsIjoiaHR0cHM6Ly9hbml3YXRjaGVyLmNvbS9zZWFyY2g/cT0lcyJ9XSwic3R5bGVTaGVldCI6Ii5wb3B1cCAuZW5naW5lLW5hbWUsIC5wb3B1cC5tYWlubWVudSA+IGxpOmZpcnN0LWNoaWxke1xuIGRpc3BsYXk6IG5vbmU7XG59XG4ucG9wdXAgYSwgLnBvcHVwIGxpe1xuIGRpc3BsYXk6IGlubGluZS1ibG9jazsgcGFkZGluZzogMC4yZW07XG59XG4ucG9wdXAgaW1ne1xuIG1hcmdpbjogMDsgcGFkZGluZzogMDtcbn1cbi5wb3B1cCB7XG4gd2lkdGg6IGF1dG87XG4gcGFkZGluZzogMC4xZW07XG4gd2hpdGUtc3BhY2U6bm93cmFwO1xufVxuLnBvcHVwIC5lbmdpbmUtc2VwYXJhdG9ye1xuIHdpZHRoOiAxcHg7IGhlaWdodDogMjBweDsgbWFyZ2luOiAwIDNweCAzcHggM3B4OyBwYWRkaW5nOiAwOyB2ZXJ0aWNhbC1hbGlnbjogbWlkZGxlO1xufVxuLypDT05GSUdfU1RBUlR7XCJzdWJtZW51X3Bvc2l0aW9uXCI6XCJ0b3ByaWdodFwiLFwic3VibWVudV9jb3JuZXJcIjpcImJvdHRvbWxlZnRcIn1DT05GSUdfRU5EKi8iLCJvcHRpb25zIjp7ImJ1dHRvbiI6MCwibmV3dGFiIjp0cnVlLCJhY3RpdmF0b3IiOiJkaXNhYmxlZCIsInJlbW92ZV9pY29ucyI6Im5vIiwic2hvd19pbl9pbnB1dHMiOnRydWUsImJhY2tncm91bmRfdGFiIjpmYWxzZSwia19hbmRfbV9jb21ibyI6WzE3LDBdLCJjb250ZXh0X21lbnUiOiJlbmFibGVkIiwidG9vbGJhcl9wb3B1cCI6ImRpc2FibGVkIiwidG9vbGJhcl9wb3B1cF9zdHlsZSI6ImRlZmF1bHQiLCJ0b29sYmFyX3BvcHVwX2hvdGtleXMiOmZhbHNlLCJ0b29sYmFyX3BvcHVwX3N1Z2dlc3Rpb25zIjp0cnVlLCJzZXBhcmF0ZV9tZW51cyI6ZmFsc2UsImhpZGVfb25fY2xpY2siOnRydWUsImRpc2FibGVfZm9ybWV4dHJhY3RvciI6dHJ1ZSwib3Blbl9vbl9kYmxjbGljayI6ZmFsc2UsImRibGNsaWNrX2luX2lucHV0cyI6dHJ1ZSwib3Blbl9uZXdfdGFiX2xhc3QiOmZhbHNlLCJkaXNhYmxlX2VmZmVjdHMiOmZhbHNlLCJhdXRvX3BvcHVwX3JlbGF0aXZlX3RvX21vdXNlIjpmYWxzZSwiYXV0b19wb3B1cF9zaG93X21lbnVfZGlyZWN0bHkiOmZhbHNlLCJhdXRvX3BvcHVwX2luX2lucHV0cyI6ZmFsc2UsImFjdGl2YXRvcl9jb21ibyI6W10sInNob3dfdG9vbHRpcHMiOmZhbHNlLCJjaXJjdWxhcl9tZW51IjpmYWxzZSwic29ydF9ieV9jbGljayI6ZmFsc2UsInNlbGVjdGlvbl9sZW5ndGhfbGltaXQiOi0xLCJhdXRvX2hpZGVfZGVsYXkiOjAsImF1dG9fb3Blbl9kZWxheSI6MzAwLCJoaWRlX29uX3Njcm9sbCI6ZmFsc2UsInNlbGVjdGlvbl9hbGxvd19uZXdsaW5lIjpmYWxzZSwidXNlX3doaXRlbGlzdCI6ZmFsc2V9LCJWRVJTSU9OIjoiMC44LjU4In0=
