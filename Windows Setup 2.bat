start ms-settings:windowsupdate-action

pause

rem Disable Indexing C:/Z:
explorer

pause

rem Set 75 Hz
rem Disable Sound Devices / Network Connection - all adapters - Uncheck all but IPv4
control

pause

rem Uninstall all but Notepad and Wordpad
start ms-settings:optionalfeatures

pause

copy "D:\Software\freeoffice2018.msi" "%USERPROFILE%\Desktop"
start "" /wait "%USERPROFILE%\Desktop\freeoffice2018.msi"
start "" /wait "D:\Software\AudialsRadio-Setup.exe"
start "" /wait "‪D:\Software\GIHO_TubeGet_Pro.exe"
start "" /wait "D:\Software\Temp\Setup\9.exe"
start "" /wait "D:\Software\Temp\Setup\10.exe" /ai

rem Disable scanning and updating Process Hacker
start "" /wait "D:\Software\Temp\Soft\Windows Repair Toolbox\Downloads\PatchMyPc\PatchMyPC.exe"
start "" /wait "D:\Software\Temp\Setup\11.exe"
start "" /wait "D:\Software\Temp\Setup\12.exe"
start "" /wait "D:\Software\Temp\Setup\13.exe"
start "" /wait "D:\Software\Temp\Setup\15.exe"
start "" /wait "D:\Software\Temp\Setup\16.exe"
start "" /wait "D:\Software\Temp\Setup\BraveBrowserSetup.exe"

taskkill /im Brave.exe /f
taskkill /im Discord.exe /f
taskkill /im Setpoint.exe /f

rem Symlink for Apps in RAMDisk
takeown /s %computername% /u %username% /f "%AppData%\Discord" /r /d y
icacls "%AppData%\Discord" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls "%AppData%\Discord" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
xcopy "%AppData%\Discord" "Z:\Discord" /s /i /y
rd "%AppData%\Discord" /s /q
mklink /d "%AppData%\Discord" "Z:\Discord"

taskkill /im Brave.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\BraveSoftware\Brave-Browser" /r /d y
rem icacls "%LocalAppData%\BraveSoftware\Brave-Browser" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rem icacls "%LocalAppData%\BraveSoftware\Brave-Browser" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
xcopy "%LocalAppData%\BraveSoftware\Brave-Browser" "Z:\Brave" /s /i /y
rd "%LocalAppData%\BraveSoftware\Brave-Browser" /s /q
mklink /d "%LocalAppData%\BraveSoftware\Brave-Browser" "Z:\Brave"

rd "Z:\Documents\Euro Truck Simulator 2\mod"
mklink /d "Z:\Documents\Euro Truck Simulator 2\mod" "D:\Euro Truck Simulator 2\mod"
rd "Z:\Documents\ETS2MP\mod"
mklink /d "Z:\Documents\ETS2MP\mod" "D:\Euro Truck Simulator 2\mods"

pause

start "" "D:\Software"

pause

start "" /wait "D:\Software\Temp\Setup\Setup.exe"
start "" /wait "D:\Software\Temp\Setup\0.reg"
taskkill /im explorer.exe /f & explorer.exe
reg add "HKLM\Software\TruckersMP" /v "InstallDir" /t REG_SZ /d "D:\TruckersMP Launcher" /f
reg add "HKLM\Software\TruckersMP" /v "InstallLocationETS2" /t REG_SZ /d "D:\Steam\steamapps\common\Euro Truck Simulator 2" /f

rem Remove All Apps except Store
rem %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppXPackage | where-object {$_.name –notlike '*store*'} | Remove-AppxPackage"

pause

start "" /wait "%ProgramFiles(x86)%\SoftMaker FreeOffice 2018\PlanMaker.exe"
start "" "D:\Software\Temp\Mikai.xlsx"
start ms-settings:yourinfo

pause

start ms-settings:appsfeatures

pause

start "" /wait "%ProgramFiles%\\BraveSoftware\Brave-Browser\Application\brave.exe"

Disabled #heavy-ad-privacy-mitigations
Disabled #tab-hover-cards
Enabled #abusive-notification-permission-revocation
Enabled #block-insecure-private-network-requests
Enabled #disallow-doc-written-script-loads
Enabled #dns-httpssvc
Enabled #enable-heavy-ad-intervention
Enabled #enable-parallel-downloading
Enabled #enable-quic
Enabled #enable-webrtc-hide-local-ips-with-mdns
Enabled #permission-chip
Enabled #permission-predictions
Enabled #quiet-notification-prompts
Enabled #turn-off-streaming-media-caching-always
Enabled #use-sync-sandbox

https://duckduckgo.com/?q=%s&k5=2&k1=-1&kav=1&kau=-1&kax=-1&kaq=-1&kah=sk-sk&kao=-1&kk=-1&kak=-1&kap=-1&kbc=1

pause

start "" /wait "D:\Steam\steam.exe"
start "" /wait "D:\Software\Temp\Setup\14.exe"
start ms-windows-store:

pause

rem Update Drivers!
rem Disable AMD PSP / AMD HDMI
rem Set Disk Drives - XPG Policies
devmgmt.msc

pause

start "" /wait "D:\Software\Temp\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\TCPOptimizer.exe"

pause

start "" /wait "D:\Software\Temp\Setup\FREEAV.exe"

rem Restart Now !

pause

rem Restart NOW !!!

pause

rem Anti-ransomware prevention, E: is read only (for backup) Administrator rights are required to modify, SYSTEM is blocked
rem https://medium.com/tenable-techblog/bypass-windows-10-user-group-policy-and-more-with-this-one-weird-trick-552d4bc5cc1b
rem This means if we set an explicit entry to “DENY” SYSTEM writable permissions, then it will effectively block “SYSTEM” from obtaining writable permissions since our “DENY” rule will take precedence over the “ALLOW” rule that it tries to add.
rem takeown /f E: /a /r /d y
rem icacls E: /inheritance:r
rem icacls E: /grant "Users":(OI)(CI)RX /t /l /q /c
rem icacls E: /deny "System":(OI)(CI)F /t /l /q /c


rem ============================ Manual Config Required / Optional =============================


rem Apply Windows Tweaks at will / <(^.^)>
rem Windows Cleanup - https://pastebin.com/5Q4t1Us9
rem Windows Defender Disable - https://pastebin.com/kYCVzZPz
rem Windows Tweaks - https://pastebin.com/m26z309a

rem Make Sure Secure Boot is ON after BIOS Update !!!!!

rem Take Ownership of the Registry key - https://www.youtube.com/watch?v=M1l5ifYKefg
rem To remove Network from Explorer/allow cleaning WebCache
rem "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder"
rem "HKCR\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}"
rem "HKCR\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}"
rem ________________________________________________________________________________________
rem "HKCR\Wow6432Node\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}"
rem "HKCR\Wow6432Node\AppID\{0358b920-0ac7-461f-98f4-58e32cd89148}"
rem "HKLM\Software\Wow6432Node\Classes\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}"
rem "HKLM\Software\Wow6432Node\Classes\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}"

rem Enhancer for Youtube
rem {"version":"2.0.103.3","settings":{"blur":0,"brightness":100,"contrast":100,"grayscale":0,"huerotate":0,"invert":0,"saturate":100,"sepia":0,"applyvideofilters":false,"backgroundcolor":"#000000","backgroundopacity":85,"blockads":true,"blockadsexceptforsubs":false,"blockautoplay":false,"blockhfrformats":false,"blockwebmformats":true,"cinemamode":false,"cinemamodewideplayer":false,"controls":["options"],"controlspeed":false,"controlspeedmousebutton":false,"controlvolume":false,"controlvolumemousebutton":false,"customcolors":{"--dimmer-text":"#cccccc","--hover-background":"#232323","--main-background":"#111111","--main-color":"#00adee","--main-text":"#eff0f1","--second-background":"#181818","--shadow":"#000000"},"customcssrules":"","customscript":"","customtheme":false,"date":1590884155282,"defaultvolume":false,"disableautoplay":false,"executescript":false,"expanddescription":false,"filter":"none","hidecardsendscreens":false,"hidechat":false,"hidecomments":false,"hiderelated":false,"ignoreplaylists":true,"ignorepopupplayer":true,"localecode":"en_US","localedir":"ltr","message":false,"miniplayer":false,"miniplayerposition":"_top-left","miniplayersize":"_400x225","newestcomments":false,"overridespeeds":false,"pauseforegroundtab":false,"pausevideos":false,"popuplayersize":"640x360","qualityembeds":"hd720","qualityembedsfullscreen":"hd1080","qualityplaylists":"hd1080","qualityplaylistsfullscreen":"hd1080","qualityvideos":"hd1080","qualityvideosfullscreen":"hd1080","reload":false,"reversemousewheeldirection":false,"selectquality":true,"selectqualityfullscreenoff":false,"selectqualityfullscreenon":false,"speed":1,"speedvariation":0.1,"stopvideos":false,"theatermode":false,"theme":"default-dark","themevariant":"youtube-deep-dark.css","update":1614801673501,"volume":50,"volumemultiplier":3,"volumevariation":5,"whitelist":"Google Chrome","wideplayer":false,"wideplayerviewport":false}}
rem Selection Search
rem eyJzZWFyY2hFbmdpbmVzIjpbeyJuYW1lIjoiWW91dHViZSIsInVybCI6Imh0dHBzOi8vd3d3LnlvdXR1YmUuY29tL3Jlc3VsdHM/c2VhcmNoX3F1ZXJ5PSVzIn0seyJuYW1lIjoiSU1EYiIsInVybCI6Imh0dHBzOi8vd3d3LmltZGIuY29tL2ZpbmQ/cz1hbGwmcT0lcyJ9LHsibmFtZSI6IlNvZnRwZWRpYSIsInVybCI6Imh0dHBzOi8vd2luLnNvZnRwZWRpYS5jb20vZHluLXNlYXJjaC5waHA/c2VhcmNoX3Rlcm09JXMifSx7Im5hbWUiOiJEaWN0aW9uYXJ5IiwidXJsIjoiaHR0cHM6Ly93d3cudGhlZnJlZWRpY3Rpb25hcnkuY29tLyVzIn0seyJuYW1lIjoiTXlBbmltZSIsInVybCI6Imh0dHBzOi8vbXlhbmltZWxpc3QubmV0L2FuaW1lLnBocD9xPSVzJmNhdD1hbmltZSJ9LHsibmFtZSI6IjEyM01vdmllcyIsInVybCI6Imh0dHBzOi8vd3c0LjAxMjNtb3ZpZS5uZXQvc2VhcmNoLyVzLmh0bWwifSx7Im5hbWUiOiJHb01vdmllcyIsInVybCI6Imh0dHBzOi8vd3cuZ28xMjNtb3ZpZXMuaW8vP3M9JXMifSx7Im5hbWUiOiJFTW92aWVzIiwidXJsIjoiaHR0cHM6Ly9lbW92aWVzLmlvL21vdmllL3NlYXJjaC8lcyJ9XSwic3R5bGVTaGVldCI6IiIsIm9wdGlvbnMiOnsiYnV0dG9uIjowLCJuZXd0YWIiOnRydWUsImFjdGl2YXRvciI6ImRpc2FibGVkIiwicmVtb3ZlX2ljb25zIjoibm8iLCJzaG93X2luX2lucHV0cyI6dHJ1ZSwiYmFja2dyb3VuZF90YWIiOmZhbHNlLCJrX2FuZF9tX2NvbWJvIjpbMTcsMF0sImNvbnRleHRfbWVudSI6ImVuYWJsZWQiLCJ0b29sYmFyX3BvcHVwIjoiZGlzYWJsZWQiLCJ0b29sYmFyX3BvcHVwX3N0eWxlIjoiZGVmYXVsdCIsInRvb2xiYXJfcG9wdXBfaG90a2V5cyI6ZmFsc2UsInRvb2xiYXJfcG9wdXBfc3VnZ2VzdGlvbnMiOnRydWUsInNlcGFyYXRlX21lbnVzIjpmYWxzZSwiaGlkZV9vbl9jbGljayI6ZmFsc2UsImRpc2FibGVfZm9ybWV4dHJhY3RvciI6dHJ1ZSwib3Blbl9vbl9kYmxjbGljayI6ZmFsc2UsImRibGNsaWNrX2luX2lucHV0cyI6dHJ1ZSwib3Blbl9uZXdfdGFiX2xhc3QiOmZhbHNlLCJkaXNhYmxlX2VmZmVjdHMiOmZhbHNlLCJhdXRvX3BvcHVwX3JlbGF0aXZlX3RvX21vdXNlIjpmYWxzZSwiYXV0b19wb3B1cF9zaG93X21lbnVfZGlyZWN0bHkiOmZhbHNlLCJhdXRvX3BvcHVwX2luX2lucHV0cyI6ZmFsc2UsImFjdGl2YXRvcl9jb21ibyI6W10sInNob3dfdG9vbHRpcHMiOmZhbHNlLCJjaXJjdWxhcl9tZW51IjpmYWxzZSwic29ydF9ieV9jbGljayI6ZmFsc2UsInNlbGVjdGlvbl9sZW5ndGhfbGltaXQiOi0xLCJhdXRvX2hpZGVfZGVsYXkiOjAsImF1dG9fb3Blbl9kZWxheSI6MzAwLCJoaWRlX29uX3Njcm9sbCI6ZmFsc2UsInNlbGVjdGlvbl9hbGxvd19uZXdsaW5lIjpmYWxzZSwidXNlX3doaXRlbGlzdCI6ZmFsc2V9LCJWRVJTSU9OIjoiMC44LjU2In0=
