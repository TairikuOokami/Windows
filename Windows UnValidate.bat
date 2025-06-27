rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!

rem Temporarily allow "ValidateAdminCodeSignatures" to allow exe without a digital signature to run as admin: "A referral was returned from the server"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f

rem Add DoH for Edge, to reset, remove the entry/policy
rem https://adguard-dns.io/kb/general/dns-providers
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://freedns.controld.com/p2?" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://zero.dns0.eu?" /f

rem Add Windows DoT
netsh dns add encryption server=76.76.2.2 dothost=p2.freedns.controld.com:853 autoupgrade=yes udpfallback=no

rem netsh dns add encryption server=193.110.81.0 dothost=zero.dns0.eu:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=185.253.5.0 dothost=zero.dns0.eu:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=45.90.28.99 dothost=FDDefine7Mini-xxxxxx.dns.nextdns.io:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=45.90.30.99 dothost=FDDefine7Mini-xxxxxx.dns.nextdns.io:853 autoupgrade=yes udpfallback=no

rem Update Time manually to deal with the broken Windows Time Sync
start "" "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\UpdateTime_x64.exe"

pause

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "1" /f
