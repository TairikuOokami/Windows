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

rem Add Windows DoT
netsh dns add encryption server=76.76.2.2 dothost=p2.freedns.controld.com:853 autoupgrade=yes udpfallback=no

rem netsh dns add encryption server=193.110.81.0 dothost=zero.dns0.eu:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=185.253.5.0 dothost=zero.dns0.eu:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=45.90.28.99 dothost=FDDefine7Mini-xxxxxx.dns.nextdns.io:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=45.90.30.99 dothost=FDDefine7Mini-xxxxxx.dns.nextdns.io:853 autoupgrade=yes udpfallback=no

rem Add Windows DoT Manually
rem reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\45.90.28.99" /v "DotFlags" /t REG_DWORD /d "4" /f
rem reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\45.90.30.99" /v "DotFlags" /t REG_DWORD /d "4" /f
rem reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\45.90.28.99" /v "DotHost" /t REG_SZ /d "FDDefine7Mini-xxxxxx.dns.nextdns.io" /f
rem reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\45.90.30.99" /v "DotHost" /t REG_SZ /d "FDDefine7Mini-xxxxxx.dns.nextdns.io" /f
rem reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\45.90.28.99" /v "DotPort" /t REG_DWORD /d "853" /f
rem reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers\45.90.30.99" /v "DotPort" /t REG_DWORD /d "853" /f

rem Add DoH for Edge, to reset, remove the entry/policy
rem https://adguard-dns.io/kb/general/dns-providers
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://freedns.controld.com/p2?" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://zero.dns0.eu?" /f
