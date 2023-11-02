rem Delete Windows Recovery Partition / Extend Windows Partition
start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Macrorit\mde-free-portable\x64\dm.exe"

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
start "" /wait "edge://settings/searchEngines"
rem https://search.brave.com/search?q=%s

pause

start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\NanaZip.lnk"
start "" "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\2fast - two factor authenticator supporting TOTP.lnk"

pause

rem https://support.brave.com/hc/en-us/articles/360044860011-How-Do-I-Use-Command-Line-Flags-in-Brave-
rem https://github.com/dreammjow/ChromiumHardening/blob/main/flags/chrome-command-line.md
rem https://peter.sh/experiments/chromium-command-line-switches
rem https://get.webgl.org / https://www.cloudflare.com/ssl/encrypted-sni
rem "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --enable-features="EnableCsrssLockdown,EncryptedClientHello,IsolatePrerenders,IsolateSandboxedIframes,RendererAppContainer,WinSboxDisableExtensionPoint" --disable-webgl --no-pings
rem C:\Users\Tairi\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe --disable-breakpad --disable-crash-reporter

rem Disabled
rem edge://flags/#allow-all-sites-to-initiate-mirroring
rem edge://flags/#edge-auto-enter-immersive-reader
rem edge://flags/#edge-automatic-profile-switching
rem edge://flags/#edge-drop
rem edge://flags/#edge-omnibox-ui-hide-steady-state-url-scheme
rem edge://flags/#edge-omnibox-ui-hide-steady-state-url-trivial-subdomains
rem edge://flags/#edge-optin-experimentation
rem edge://flags/#edge-prenav
rem edge://flags/#edge-reading-view
rem edge://flags/#edge-share-menu
rem edge://flags/#edge-show-feature-recommendations
rem edge://flags/#edge-split-screen
rem edge://flags/#enable-quic
rem edge://flags/#enable-windows-gaming-input-data-fetcher
rem edge://flags/#media-router-cast-allow-all-ips

rem Enabled
rem edge://flags/#block-insecure-private-network-requests
rem edge://flags/#disallow-doc-written-script-loads
rem edge://flags/#edge-auth-manager-delay-load
rem edge://flags/#edge-autoplay-user-setting-block-option
rem edge://flags/#edge-reduce-user-agent-minor-version
rem edge://flags/#enable-first-party-sets
rem edge://flags/#partitioned-cookies
rem edge://flags/#strict-origin-isolation
rem edge://flags/#edge-toast-winrt
rem edge://flags/#use-dns-https-svcb-alpn


pause

reg add "HKLM\Software\TruckersMP" /v "InstallDir" /t REG_SZ /d "C:\Program Files\TruckersMP Launcher" /f
reg add "HKLM\Software\TruckersMP" /v "InstallLocationETS2" /t REG_SZ /d "D:\Steam\steamapps\common\Euro Truck Simulator 2" /f
start "" /wait "D:\Steam\steam.exe"
start "" /wait "D:\OneDrive\Setup\TruckersMP-Setup.exe"

rem Steam Interface - Disable Everything

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
rem Disable System Devices - AMD Crash Defender, AMD Link, AMD SMBus, Composite Bus Enumerator, MS Hyper-V, NDIS Virtual, Remote Desktop, System Speaker, UMBus
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

rem Selection Search eyJzZWFyY2hFbmdpbmVzIjpbeyJuYW1lIjoiSU1EYiIsInVybCI6Imh0dHBzOi8vd3d3LmltZGIuY29tL2ZpbmQ/cz1hbGwmcT0lcyJ9LHsibmFtZSI6IlNvZnRwZWRpYSIsInVybCI6Imh0dHBzOi8vd2luLnNvZnRwZWRpYS5jb20vZHluLXNlYXJjaC5waHA/c2VhcmNoX3Rlcm09JXMifSx7Im5hbWUiOiJEaWN0aW9uYXJ5IiwidXJsIjoiaHR0cHM6Ly93d3cubWVycmlhbS13ZWJzdGVyLmNvbS9kaWN0aW9uYXJ5LyVzIn0seyJuYW1lIjoiMTIzTW92aWVzIiwidXJsIjoiaHR0cHM6Ly93dzUuMDEyM21vdmllLm5ldC9zZWFyY2guaHRtbD9xPSVzIn0seyJuYW1lIjoiU0ZsaXgiLCJ1cmwiOiJodHRwczovL3d3dzEuc2ZsaXgud2F0Y2gvP3M9JXMifSx7Im5hbWUiOiJQdXRsb2NrZXIiLCJ1cmwiOiJodHRwczovL3B1dGxvY2tlci5neS9zZWFyY2gvJXMifSx7Im5hbWUiOiJNeUFuaW1lIiwidXJsIjoiaHR0cHM6Ly9teWFuaW1lbGlzdC5uZXQvYW5pbWUucGhwP3E9JXMmY2F0PWFuaW1lIn0seyJuYW1lIjoiQW5pV2F0Y2hlciIsInVybCI6Imh0dHBzOi8vYW5pd2F0Y2hlci5jb20vc2VhcmNoP3E9JXMifV0sInN0eWxlU2hlZXQiOiIucG9wdXAgLmVuZ2luZS1uYW1lLCAucG9wdXAubWFpbm1lbnUgPiBsaTpmaXJzdC1jaGlsZHtcbiBkaXNwbGF5OiBub25lO1xufVxuLnBvcHVwIGEsIC5wb3B1cCBsaXtcbiBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7IHBhZGRpbmc6IDAuMmVtO1xufVxuLnBvcHVwIGltZ3tcbiBtYXJnaW46IDA7IHBhZGRpbmc6IDA7XG59XG4ucG9wdXAge1xuIHdpZHRoOiBhdXRvO1xuIHBhZGRpbmc6IDAuMWVtO1xuIHdoaXRlLXNwYWNlOm5vd3JhcDtcbn1cbi5wb3B1cCAuZW5naW5lLXNlcGFyYXRvcntcbiB3aWR0aDogMXB4OyBoZWlnaHQ6IDIwcHg7IG1hcmdpbjogMCAzcHggM3B4IDNweDsgcGFkZGluZzogMDsgdmVydGljYWwtYWxpZ246IG1pZGRsZTtcbn1cbi8qQ09ORklHX1NUQVJUe1wic3VibWVudV9wb3NpdGlvblwiOlwidG9wcmlnaHRcIixcInN1Ym1lbnVfY29ybmVyXCI6XCJib3R0b21sZWZ0XCJ9Q09ORklHX0VORCovIiwib3B0aW9ucyI6eyJidXR0b24iOjAsIm5ld3RhYiI6dHJ1ZSwiYWN0aXZhdG9yIjoiZGlzYWJsZWQiLCJyZW1vdmVfaWNvbnMiOiJubyIsInNob3dfaW5faW5wdXRzIjp0cnVlLCJiYWNrZ3JvdW5kX3RhYiI6ZmFsc2UsImtfYW5kX21fY29tYm8iOlsxNywwXSwiY29udGV4dF9tZW51IjoiZW5hYmxlZCIsInRvb2xiYXJfcG9wdXAiOiJkaXNhYmxlZCIsInRvb2xiYXJfcG9wdXBfc3R5bGUiOiJkZWZhdWx0IiwidG9vbGJhcl9wb3B1cF9ob3RrZXlzIjpmYWxzZSwidG9vbGJhcl9wb3B1cF9zdWdnZXN0aW9ucyI6dHJ1ZSwic2VwYXJhdGVfbWVudXMiOmZhbHNlLCJoaWRlX29uX2NsaWNrIjp0cnVlLCJkaXNhYmxlX2Zvcm1leHRyYWN0b3IiOnRydWUsIm9wZW5fb25fZGJsY2xpY2siOmZhbHNlLCJkYmxjbGlja19pbl9pbnB1dHMiOnRydWUsIm9wZW5fbmV3X3RhYl9sYXN0IjpmYWxzZSwiZGlzYWJsZV9lZmZlY3RzIjpmYWxzZSwiYXV0b19wb3B1cF9yZWxhdGl2ZV90b19tb3VzZSI6ZmFsc2UsImF1dG9fcG9wdXBfc2hvd19tZW51X2RpcmVjdGx5IjpmYWxzZSwiYXV0b19wb3B1cF9pbl9pbnB1dHMiOmZhbHNlLCJhY3RpdmF0b3JfY29tYm8iOltdLCJzaG93X3Rvb2x0aXBzIjpmYWxzZSwiY2lyY3VsYXJfbWVudSI6ZmFsc2UsInNvcnRfYnlfY2xpY2siOmZhbHNlLCJzZWxlY3Rpb25fbGVuZ3RoX2xpbWl0IjotMSwiYXV0b19oaWRlX2RlbGF5IjowLCJhdXRvX29wZW5fZGVsYXkiOjMwMCwiaGlkZV9vbl9zY3JvbGwiOmZhbHNlLCJzZWxlY3Rpb25fYWxsb3dfbmV3bGluZSI6ZmFsc2UsInVzZV93aGl0ZWxpc3QiOmZhbHNlLCJ1c2VfYmxhY2tsaXN0X2Zvcl9ob3RrZXlzIjp0cnVlfSwiVkVSU0lPTiI6IjAuOC42NCJ9
