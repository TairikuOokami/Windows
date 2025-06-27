rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!

rem Clean Desktop/Downloads/RAMdisk/TOR with 1-click to prevent malware or files falling into the wrong hands :)

rem Run once as admin to take the ownership, then it can be run as the user
takeown /s %computername% /u %username% /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

taskkill /im firefox.exe /f
taskkill /im tor.exe /f

timeout 1

del "%SystemDrive%\Users\Public\Desktop\*" /s /f /q
del "%USERPROFILE%\Desktop\*" /s /f /q
del "Z:\Temp\*" /s /f /q

rd "%USERPROFILE%\Desktop" /s /q
md "%USERPROFILE%\Desktop"

rd "Z:\Temp" /s /q
md "Z:\Temp"
