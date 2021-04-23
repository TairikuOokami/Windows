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

taskkill /im msedge.exe /f
taskkill /im Setpoint.exe /f
takeown /s %computername% /u %username% /f "%LocalAppData%\Microsoft\Edge" /r /d y
rem icacls "%LocalAppData%\Microsoft\Edge" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rem icacls "%LocalAppData%\Microsoft\Edge" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
xcopy "%LocalAppData%\Microsoft\Edge" "Z:\Edge" /s /i /y
rd "%LocalAppData%\Microsoft\Edge" /s /q
mklink /d "%LocalAppData%\Microsoft\Edge" "Z:\Edge"

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

start "" /wait "%ProgramFiles(x86)%\Microsoft\Edge Beta\Application\msedge.exe"

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
rem {"version":"2.0.104.8","settings":{"blur":0,"brightness":100,"contrast":100,"grayscale":0,"huerotate":0,"invert":0,"saturate":100,"sepia":0,"applyvideofilters":false,"backgroundcolor":"#000000","backgroundopacity":50,"blackbars":false,"blockads":true,"blockadsexceptforsubs":false,"blockautoplay":false,"blockhfrformats":false,"blockwebmformats":true,"cinemamode":false,"cinemamodewideplayer":false,"controlbar":{"active":true,"autohide":false,"centered":true,"position":"fixed"},"controls":[],"controlsvisible":false,"controlspeed":false,"controlspeedmousebutton":false,"controlvolume":false,"controlvolumemousebutton":false,"customcolors":{"--dimmer-text":"#cccccc","--hover-background":"#232323","--main-background":"#111111","--main-color":"#00adee","--main-text":"#eff0f1","--second-background":"#181818","--shadow":"#000000"},"customcssrules":"","customscript":"","customtheme":false,"darktheme":true,"date":1590884155282,"defaultvolume":false,"disableautoplay":false,"executescript":false,"expanddescription":false,"filter":"none","hidecardsendscreens":false,"hidechat":false,"hidecomments":false,"hiderelated":false,"ignoreplaylists":false,"ignorepopupplayer":true,"localecode":"en_US","localedir":"ltr","message":true,"miniplayer":false,"miniplayerposition":"_top-left","miniplayersize":"_400x225","newestcomments":false,"overridespeeds":false,"pauseforegroundtab":false,"pausevideos":false,"popuplayersize":"640x360","qualityembeds":"hd720","qualityembedsfullscreen":"hd1080","qualityplaylists":"hd1080","qualityplaylistsfullscreen":"hd1080","qualityvideos":"hd1080","qualityvideosfullscreen":"hd1080","reload":false,"reversemousewheeldirection":false,"selectquality":true,"selectqualityfullscreenoff":false,"selectqualityfullscreenon":false,"speed":1,"speedvariation":0.1,"stopvideos":false,"theatermode":false,"theme":"default-dark","themevariant":"youtube-deep-dark.css","update":1619098163598,"volume":50,"volumemultiplier":3,"volumevariation":5,"whitelist":"","wideplayer":false,"wideplayerviewport":false}}

rem eyJzZWFyY2hFbmdpbmVzIjpbeyJuYW1lIjoiWW91dHViZSIsInVybCI6Imh0dHBzOi8vd3d3LnlvdXR1YmUuY29tL3Jlc3VsdHM/c2VhcmNoX3F1ZXJ5PSVzIn0seyJuYW1lIjoiSU1EYiIsInVybCI6Imh0dHBzOi8vd3d3LmltZGIuY29tL2ZpbmQ/cz1hbGwmcT0lcyJ9LHsibmFtZSI6IlNvZnRwZWRpYSIsInVybCI6Imh0dHBzOi8vd2luLnNvZnRwZWRpYS5jb20vZHluLXNlYXJjaC5waHA/c2VhcmNoX3Rlcm09JXMifSx7Im5hbWUiOiJEaWN0aW9uYXJ5IiwidXJsIjoiaHR0cHM6Ly93d3cudGhlZnJlZWRpY3Rpb25hcnkuY29tLyVzIn0seyJuYW1lIjoibTR1ZnJlZSIsInVybCI6Imh0dHBzOi8vbTR1ZnJlZS50by9zZWFyY2gvJXMuaHRtbCJ9LHsibmFtZSI6IjEyM01vdmllcyIsInVybCI6Imh0dHBzOi8vd3c1LjAxMjNtb3ZpZS5uZXQvc2VhcmNoLyVzLmh0bWwifSx7Im5hbWUiOiJHb01vdmllcyIsInVybCI6Imh0dHBzOi8vd3cuZ28xMjNtb3ZpZXMuaW8vP3M9JXMifSx7Im5hbWUiOiJNeUFuaW1lIiwidXJsIjoiaHR0cHM6Ly9teWFuaW1lbGlzdC5uZXQvYW5pbWUucGhwP3E9JXMmY2F0PWFuaW1lIn1dLCJzdHlsZVNoZWV0IjoiIiwib3B0aW9ucyI6eyJidXR0b24iOjAsIm5ld3RhYiI6dHJ1ZSwiYWN0aXZhdG9yIjoiZGlzYWJsZWQiLCJyZW1vdmVfaWNvbnMiOiJubyIsInNob3dfaW5faW5wdXRzIjp0cnVlLCJiYWNrZ3JvdW5kX3RhYiI6ZmFsc2UsImtfYW5kX21fY29tYm8iOlsxNywwXSwiY29udGV4dF9tZW51IjoiZW5hYmxlZCIsInRvb2xiYXJfcG9wdXAiOiJkaXNhYmxlZCIsInRvb2xiYXJfcG9wdXBfc3R5bGUiOiJkZWZhdWx0IiwidG9vbGJhcl9wb3B1cF9ob3RrZXlzIjpmYWxzZSwidG9vbGJhcl9wb3B1cF9zdWdnZXN0aW9ucyI6dHJ1ZSwic2VwYXJhdGVfbWVudXMiOmZhbHNlLCJoaWRlX29uX2NsaWNrIjpmYWxzZSwiZGlzYWJsZV9mb3JtZXh0cmFjdG9yIjp0cnVlLCJvcGVuX29uX2RibGNsaWNrIjpmYWxzZSwiZGJsY2xpY2tfaW5faW5wdXRzIjp0cnVlLCJvcGVuX25ld190YWJfbGFzdCI6ZmFsc2UsImRpc2FibGVfZWZmZWN0cyI6ZmFsc2UsImF1dG9fcG9wdXBfcmVsYXRpdmVfdG9fbW91c2UiOmZhbHNlLCJhdXRvX3BvcHVwX3Nob3dfbWVudV9kaXJlY3RseSI6ZmFsc2UsImF1dG9fcG9wdXBfaW5faW5wdXRzIjpmYWxzZSwiYWN0aXZhdG9yX2NvbWJvIjpbXSwic2hvd190b29sdGlwcyI6ZmFsc2UsImNpcmN1bGFyX21lbnUiOmZhbHNlLCJzb3J0X2J5X2NsaWNrIjpmYWxzZSwic2VsZWN0aW9uX2xlbmd0aF9saW1pdCI6LTEsImF1dG9faGlkZV9kZWxheSI6MCwiYXV0b19vcGVuX2RlbGF5IjozMDAsImhpZGVfb25fc2Nyb2xsIjpmYWxzZSwic2VsZWN0aW9uX2FsbG93X25ld2xpbmUiOmZhbHNlLCJ1c2Vfd2hpdGVsaXN0IjpmYWxzZX0sIlZFUlNJT04iOiIwLjguNTcifQ==
