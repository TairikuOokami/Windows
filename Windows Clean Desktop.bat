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
del "C:\Users\Tairi\OneDrive\Desktop\*" /s /f /q
del "%USERPROFILE%\Desktop\*" /s /f /q
rd "C:\Users\Tairi\OneDrive\Desktop" /s /q
rd "%USERPROFILE%\Desktop" /s /q
md "C:\Users\Tairi\OneDrive\Desktop"
md "%USERPROFILE%\Desktop"

del "Z:\Temp\*" /s /f /q
rd "Z:\Temp" /s /q
md "Z:\Temp"

rem Add Windows DoT
netsh dns set global doh=no
netsh dns add global dot=yes ddr=no
netsh dns set global dot=yes ddr=no
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "0" /f
netsh dns add encryption server=94.140.14.14 dothost=dns.adguard-dns.com:853 autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dothost=dns.adguard-dns.com:853 autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.14.14 dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no

rem Add DoH for Edge, to reset, remove the entry/policy
rem https://adguard-dns.io/kb/general/dns-providers
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://dns.adguard-dns.com/dns-query?" /f

ipconfig /flushdns

