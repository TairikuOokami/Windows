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

rem Disabled #edge-omnibox-ui-hide-steady-state-url-scheme
rem Disabled #edge-omnibox-ui-hide-steady-state-url-trivial-subdomains
rem Disabled #edge-share-menu
rem Disabled #edge-show-feature-recommendations
rem Disabled #enable-quic
rem Enabled #block-insecure-private-network-requests
rem Enabled #disallow-doc-written-script-loads
rem Enabled #edge-automatic-https
rem Enabled #edge-autoplay-user-setting-block-option
rem Enabled #edge-overlay-scrollbars-win-style
rem Enabled #edge-visual-rejuv-materials-menu
rem Enabled #edge-visual-rejuv-show-settings
rem Enabled #partitioned-cookies
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

rem Selection Search eyJzZWFyY2hFbmdpbmVzIjpbeyJuYW1lIjoiWW91dHViZSIsInVybCI6Imh0dHBzOi8vd3d3LnlvdXR1YmUuY29tL3Jlc3VsdHM/c2VhcmNoX3F1ZXJ5PSVzIn0seyJuYW1lIjoiSU1EYiIsInVybCI6Imh0dHBzOi8vd3d3LmltZGIuY29tL2ZpbmQ/cz1hbGwmcT0lcyJ9LHsibmFtZSI6IlNvZnRwZWRpYSIsInVybCI6Imh0dHBzOi8vd2luLnNvZnRwZWRpYS5jb20vZHluLXNlYXJjaC5waHA/c2VhcmNoX3Rlcm09JXMifSx7Im5hbWUiOiJEaWN0aW9uYXJ5IiwidXJsIjoiaHR0cHM6Ly93d3cubWVycmlhbS13ZWJzdGVyLmNvbS9kaWN0aW9uYXJ5LyVzIn0seyJuYW1lIjoibTR1ZnJlZSIsInVybCI6Imh0dHBzOi8vbTR1ZnJlZS50by9zZWFyY2gvJXMuaHRtbCJ9LHsibmFtZSI6IjEyM01vdmllcyIsInVybCI6Imh0dHBzOi8vd3c1LjAxMjNtb3ZpZS5uZXQvc2VhcmNoLyVzLmh0bWwifSx7Im5hbWUiOiIxMjNTZXJpZXMiLCJ1cmwiOiJodHRwczovLzEyM3Nlcmllcy5uZXQvc2VhcmNoP2tleXdvcmQ9JXMifSx7Im5hbWUiOiJNeUFuaW1lIiwidXJsIjoiaHR0cHM6Ly9teWFuaW1lbGlzdC5uZXQvYW5pbWUucGhwP3E9JXMmY2F0PWFuaW1lIn1dLCJzdHlsZVNoZWV0IjoiLnBvcHVwIC5lbmdpbmUtbmFtZSwgLnBvcHVwLm1haW5tZW51ID4gbGk6Zmlyc3QtY2hpbGR7XG4gZGlzcGxheTogbm9uZTtcbn1cbi5wb3B1cCBhLCAucG9wdXAgbGl7XG4gZGlzcGxheTogaW5saW5lLWJsb2NrOyBwYWRkaW5nOiAwLjJlbTtcbn1cbi5wb3B1cCBpbWd7XG4gbWFyZ2luOiAwOyBwYWRkaW5nOiAwO1xufVxuLnBvcHVwIHtcbiB3aWR0aDogYXV0bztcbiBwYWRkaW5nOiAwLjFlbTtcbiB3aGl0ZS1zcGFjZTpub3dyYXA7XG59XG4ucG9wdXAgLmVuZ2luZS1zZXBhcmF0b3J7XG4gd2lkdGg6IDFweDsgaGVpZ2h0OiAyMHB4OyBtYXJnaW46IDAgM3B4IDNweCAzcHg7IHBhZGRpbmc6IDA7IHZlcnRpY2FsLWFsaWduOiBtaWRkbGU7XG59XG4vKkNPTkZJR19TVEFSVHtcInN1Ym1lbnVfcG9zaXRpb25cIjpcInRvcHJpZ2h0XCIsXCJzdWJtZW51X2Nvcm5lclwiOlwiYm90dG9tbGVmdFwifUNPTkZJR19FTkQqLyIsIm9wdGlvbnMiOnsiYnV0dG9uIjowLCJuZXd0YWIiOnRydWUsImFjdGl2YXRvciI6ImRpc2FibGVkIiwicmVtb3ZlX2ljb25zIjoibm8iLCJzaG93X2luX2lucHV0cyI6dHJ1ZSwiYmFja2dyb3VuZF90YWIiOmZhbHNlLCJrX2FuZF9tX2NvbWJvIjpbMTcsMF0sImNvbnRleHRfbWVudSI6ImVuYWJsZWQiLCJ0b29sYmFyX3BvcHVwIjoiZGlzYWJsZWQiLCJ0b29sYmFyX3BvcHVwX3N0eWxlIjoiZGVmYXVsdCIsInRvb2xiYXJfcG9wdXBfaG90a2V5cyI6ZmFsc2UsInRvb2xiYXJfcG9wdXBfc3VnZ2VzdGlvbnMiOnRydWUsInNlcGFyYXRlX21lbnVzIjpmYWxzZSwiaGlkZV9vbl9jbGljayI6dHJ1ZSwiZGlzYWJsZV9mb3JtZXh0cmFjdG9yIjp0cnVlLCJvcGVuX29uX2RibGNsaWNrIjpmYWxzZSwiZGJsY2xpY2tfaW5faW5wdXRzIjp0cnVlLCJvcGVuX25ld190YWJfbGFzdCI6ZmFsc2UsImRpc2FibGVfZWZmZWN0cyI6ZmFsc2UsImF1dG9fcG9wdXBfcmVsYXRpdmVfdG9fbW91c2UiOmZhbHNlLCJhdXRvX3BvcHVwX3Nob3dfbWVudV9kaXJlY3RseSI6ZmFsc2UsImF1dG9fcG9wdXBfaW5faW5wdXRzIjpmYWxzZSwiYWN0aXZhdG9yX2NvbWJvIjpbXSwic2hvd190b29sdGlwcyI6ZmFsc2UsImNpcmN1bGFyX21lbnUiOmZhbHNlLCJzb3J0X2J5X2NsaWNrIjpmYWxzZSwic2VsZWN0aW9uX2xlbmd0aF9saW1pdCI6LTEsImF1dG9faGlkZV9kZWxheSI6MCwiYXV0b19vcGVuX2RlbGF5IjozMDAsImhpZGVfb25fc2Nyb2xsIjpmYWxzZSwic2VsZWN0aW9uX2FsbG93X25ld2xpbmUiOmZhbHNlLCJ1c2Vfd2hpdGVsaXN0IjpmYWxzZX0sIlZFUlNJT04iOiIwLjguNTgifQ==
