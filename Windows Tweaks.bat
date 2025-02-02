rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!


rem Create a system backup to reverse any changes
rem https://www.easyuefi.com/backup-software/tutorial/add-remove-boot-menu.html

rem "ValidateAdminCodeSignatures" will prevent exe without a digital signature to run as admin: "A referral was returned from the server"
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
rem Radio Management Service (RmSvc) is required to be able to see and to connect to WiFi networks

rem Critical processes removed - SearchHost.exe/StartMenuExperienceHost.exe
rem DNS/TCP/UDP are blocked - netsh advfirewall firewall delete rule name=all
rem DoH disabled/DoT enabled - To Disable DoT run - netsh dns add global dot=no

rem To be able to install Insider updates, you need to enable:
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "3" /f
rem bcdedit /set flightsigning on
rem bcdedit /set {bootmgr} flightsigning on

rem News - https://learn.microsoft.com/en-us/windows/release-health
rem DNS Poison enforced by the government (pick your poison/DNS) - https://torrentfreak.com/google-cloudflare-cisco-will-poison-dns-to-stop-piracy-block-circumvention-240613
rem https://techblog.nexxwave.eu/public-dns-malware-filters-tested-in-september-2024
rem AI Imposter - https://youtu.be/WT8NJk1onC8 / Deep Fake - https://youtu.be/rGIz3Z-QjMQ
rem https://www.pandasecurity.com/en/mediacenter/how-the-eu-is-about-to-violate-your-privacy
rem https://techcrunch.com/2024/05/08/encrypted-services-apple-proton-and-wire-helped-spanish-police-identify-activist
rem https://www.91mobiles.com/hub/exclusive-google-find-my-device-feature-phone-off
rem https://securuscomms.co.uk/how-hackers-bypass-two-factor-authentication - https://youtu.be/V-lSqR_rj78


rem ________________________________________________________________________________________


rem Basic informations
rem Software recommendations

rem Remove various folders, startup entries and policies
rem Restore essential startup entries

rem Software Setup
rem Windows Setup plus Manual Config

rem Windows Defender Security Center
rem Windows Error Reporting
rem Windows Explorer
rem Windows Optimizations
rem Windows Policies (Edge)
rem Windows Scheduled Tasks
rem Windows Services
rem Windows Settings
rem Windows Shell
rem Windows Store
rem Windows Support
rem Windows Waypoint


rem ================================= Basic informations ===================================


rem SeDebugPrivilege/SeTcbPrivilege - https://youtu.be/hZKLEw-Our4 - Self-elevation to System (even on SUA) used by ransomware (NotPetya/WannaCry)
rem https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system
rem https://unifiedguru.com/blackmatter-ransomware-analysis-the-dark-side-returns

rem Adblock Detection - https://www.detectadblock.com / https://blockads.fivefilters.org
rem Browser Leaks - https://browserleaks.com / CanvasFingerprint / WebRTC
rem Browser Tracking Test - https://panopticlick.eff.org
rem Privacy Cloud - https://www.technologyreview.com/2022/07/15/1056042/chinese-novel-censored-before-shared
rem Privacy Cloud - https://www.nytimes.com/2022/08/21/technology/google-surveillance-toddler-photo.html
rem Privacy CNAME - https://www.ghacks.net/2020/11/17/brave-browser-gets-cname-based-adblocking-support
rem Privacy Etags - https://lucb1e.com/randomprojects/cookielesscookies / https://fpresearch.httpjames.space
rem Privacy Futile (Encryption) - https://www.bleepingcomputer.com/news/security/an-encrypted-zip-file-can-have-two-correct-passwords-heres-why
rem Privacy Futile (GAFAM) https://askleo.com/how-does-facebook-track-me-even-if-i-dont-have-an-account
rem Privacy Futile (TOR+Tails) - https://www.vice.com/en/article/v7gd9b/facebook-helped-fbi-hack-child-predator-buster-hernandez
rem Privacy Google FLoC - https://amifloced.org / https://brave.com/why-brave-disables-floc
rem Privacy Guides - https://privacyguides.org
rem Privacy Webpage Scan - https://themarkup.org/blacklight
rem Privacy Webpage Scan - https://webbkoll.5july.net
rem SSL/TLS Test - https://www.ssllabs.com/ssltest

rem AV Comparison
rem https://www.programmifree.com/confronti
rem https://avlab.pl/en/recent-results
rem https://www.av-comparatives.org/latest-tests
rem https://www.av-test.org/en/antivirus/home-windows
rem https://www.mrg-effitas.com/test-library/
rem https://www.lifewire.com/best-free-antivirus-software-4151895

rem AVs/SSL Filtering - https://adguard.com/en/blog/everything-about-https-filtering.html - https://badssl.com
rem AV is as vulnerable as any other software, but since it uses SYSTEM rights, it is more dangerous - https://www.darkreading.com/threat-intelligence/windows-doubleagent-attack-turns-av-tools-into-malware
rem Disable webfiltering, AV replacing legitimate certificates - https://www.eff.org/deeplinks/2015/02/dear-software-vendors-please-stop-trying-intercept-your-customers-encrypted
rem MD NeverEnding Story https://www.bleepingcomputer.com/news/security/12-year-old-windows-defender-bug-gives-hackers-admin-rights/
rem https://www.bleepingcomputer.com/news/security/smartservice-and-s5mark-acts-like-an-adware-bodyguard-by-blocking-antivirus-software/
rem https://blog.emsisoft.com/2015/01/17/has-the-antivirus-industry-gone-mad
rem https://www.makeuseof.com/tag/antivirus-tracking-youd-surprised-sends/

rem DNS Benchmark / Namebench - https://code.google.com/archive/p/namebench/downloads
rem DNS Check / https://dnscheck.tools / https://www.dnsperf.com
rem DNS Domains / https://umbrella.cisco.com/blog/on-the-trail-of-malicious-dynamic-dns-domains
rem DNS Hijack / https://sockpuppet.org/blog/2015/01/15/against-dnssec / https://recdnsfp.github.io
rem DNS Encryption (setup DNS server as 127.0.0.1) - https://simplednscrypt.org + https://github.com/DNSCrypt/dnscrypt-proxy
rem DNS ECH - Good-bye ESNI, hello ECH! - https://www.cloudflare.com/ssl/encrypted-sni / https://defo.ie/ech-check.php
rem DNS Fix / DNS-Lock - https://www.sordum.org/9432/dns-lock-v1-5/
rem DNS List - https://adguard-dns.io/kb/general/dns-providers

rem Family Filtering (adult/proxy/search)
rem Adguard - https://adguard.com/en/adguard-dns/overview.html
rem Cloudflare - https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families/setup-instructions/windows/
rem CleanBrowsing - https://cleanbrowsing.org/ip-address - https://categorify.org/recategorize
rem DNS Family - https://dnsforfamily.com/#DNS_Servers
rem Enforce Safe Search (=Adult Filter) - https://chrome.google.com/webstore/detail/enforce-safe-search-adult/fiopkogmohpinncfhneadmpkcikmgkgc
rem NextDNS - https://www.nextdns.io / https://test.nextdns.io / https://ping.nextdns.io
rem OpenDNS - https://www.opendns.com/setupguide/#familyshield

rem VPN Comparison / Anonymity
rem Don't use VPN services - https://gist.github.com/joepie91/5a9909939e6ce7d09e29
rem https://arstechnica.com/tech-policy/2017/03/senate-votes-to-let-isps-sell-your-web-browsing-history-to-advertisers
rem https://sec.hpi.de/ilc/search
rem https://www.safetydetectives.com/best-vpns
rem https://www.av-comparatives.org/tests/vpn-report-2020-35-services/

rem Windows ISO - to create a local account use this email - no@thankyou.com
rem https://os.click
rem https://genuine-iso-verifier.weebly.com
rem https://massgrave.dev/genuine-installation-media.html

rem Check ISO Windows versions and build version
rem dism /Get-WimInfo /WimFile:F:\sources\install.wim
rem dism /Get-WimInfo /WimFile:F:\sources\install.wim /index:1
rem dism /Get-WimInfo /WimFile:F:\sources\install.esd /index:1

rem https://www.elevenforum.com/t/create-shortcuts-to-open-pages-in-settings-in-windows-11.522
rem https://www.elevenforum.com/t/keyboard-shortcuts-in-windows-11.2253
rem https://www.elevenforum.com/t/list-of-uri-commands-to-open-microsoft-store-apps-in-windows-11.2683
rem https://www.elevenforum.com/t/list-of-windows-11-clsid-key-guid-shortcuts.1075
rem https://www.elevenforum.com/t/list-of-windows-11-shell-commands-for-shell-folder-shortcuts.1080


rem =============================== Software recommendations ===============================


rem AntiVirus software (Avoid junk like Avira, Bitdefender, Kaspersky, Tencent)
rem 360 Total Security (CN) - https://www.360totalsecurity.com - https://ibb.co/2Mk623n
rem Microsoft Defender (US) - https://www.defenderui.com - https://ibb.co/zr8hL1n
rem Panda  (ES) - https://www.pandasecurity.com/en/homeusers/free-antivirus - https://ibb.co/dPJw4zp

rem AntiVirus software - additional protection (can be run alongside of realtime AV)
rem AppCheck (KR) - https://www.checkmal.com/product/appcheck
rem CatchPulse Lite (SG) - https://www.secureage.com/products/home-malware-protection
rem Hard Configurator - https://github.com/AndyFul/Hard_Configurator
rem KeyScrambler (US) - https://www.qfxsoftware.com
rem NeuShield Data Sentinel (US) - https://www.neushield.com/products/#prod-table

rem Browser Extensions useful against (99% malware comes via an email or a browser)
rem CDN (Chrome/Firefox/Opera) - https://decentraleyes.org
rem Cookie Warnings (Chrome/Edge/Firefox) - https://www.cookie-dialog-monster.com
rem Cookie Warnings (Chrome/Edge/Firefox) - https://www.i-dont-care-about-cookies.eu
rem Filter Lists - https://filterlists.com
rem Malware (Chrome/Firefox) - https://www.bitdefender.com/solutions/trafficlight.html
rem Malware (Chrome/Edge/Firefox) - https://microsoftedge.microsoft.com/addons/detail/emsisoft-browser-security/jlpdpddffjddlfdbllimedpemaodbjgn
rem Phishing (Chrome/Edge/Firefox/Opera) - https://www.netcraft.com/apps/browser
rem Phishing (Chrome/Edge/Firefox/Opera) - SafeToOpen - https://safetoopen.com

rem Cleanup software
rem Driver Store Explorer - https://github.com/lostindark/DriverStoreExplorer/releases
rem HiBit Uninstaller - https://hibitsoft.ir
rem Wise Disk Cleaner - https://www.wisecleaner.com/wise-disk-cleaner.html
rem Wise Registry Cleaner - https://www.wisecleaner.com/wise-registry-cleaner.html

rem Firewall software using Windows Firewall
rem Fort Firewall (US) - https://github.com/tnodir/fort
rem Simplewall (US) - https://github.com/henrypp/simplewall
rem Windows Firewall Control (US) - https://www.binisoft.org/wfc.php

rem Sandbox software
rem 360 Total Security Essential (CN) - https://www.360totalsecurity.com/en/features/360-total-security-essential
rem Comodo Antivirus (US) - https://antivirus.comodo.com/free-antivirus.php
rem Sandboxie - https://github.com/sandboxie-plus/Sandboxie

rem Security cleanup software (portable on-demand scanners, some still leave traces/drivers)
rem Antivirus Rescue Disks - https://www.techradar.com/in/best/best-antivirus-rescue-disk
rem AdwCleaner (US) - https://www.malwarebytes.com/adwcleaner/
rem Dr.Web CureIt (RU) - https://free.drweb.com/download+cureit+free
rem Emsisoft Emergency Kit (NZ) - https://www.emsisoft.com/en/home/emergency-kit
rem Kaspersky Virus Removal Tool (RU) - https://www.kaspersky.com/downloads/free-virus-removal-tool
rem Microsoft Safety Scanner (US) - https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download
rem RKill (BleepingComputer) - https://www.bleepingcomputer.com/download/rkill/

rem Security cleanup software (online/updatable on-demand scanners)
rem ESET Online Scanner (SK) - https://www.eset.com/us/home/online-scanner
rem F-Secure Online Scanner (US) - https://www.f-secure.com/en/home/free-tools/online-scanner
rem Norton Power Eraser (US) - https://support.norton.com/sp/static/external/tools/npe.html
rem Panda Cloud Cleaner (ES) - https://www.pandasecurity.com/en/homeusers/cloud-cleaner
rem Sophos Scan & Clean alas HitmanPro (UK) - https://www.sophos.com/en-us/free-tools/virus-removal-tool
rem Trend Micro HouseCall (US) - https://www.trendmicro.com/en_us/forHome/products/housecall.html

rem Software
rem 2FA / 2fast - two factor authenticator supporting TOTP - https://apps.microsoft.com/store/detail/2fast-%E2%80%93-two-factor-authenticator-supporting-totp/9P9D81GLH89Q
rem Application Updates / App Installer (winget) - https://www.microsoft.com/en-us/p/app-installer/9nblggh4nns1#activetab=pivot:overviewtab
rem Application Updates / App Installer GUI (winget) - https://www.marticliment.com/wingetui - https://winget.run
rem Bandwidth Meter / NetTraffic - https://www.venea.net/web/nettraffic
rem Bandwidth Monitor / TrafficMonitor - https://github.com/zhongyang219/TrafficMonitor/blob/master/README_en-us.md
rem Bootable USB / Rufus - https://apps.microsoft.com/store/detail/rufus/9PC3H3V7Q9CH?hl=en-us&gl=US
rem Bootloader / EasyUEFI - https://www.softpedia.com/get/System/Boot-Manager-Disk/EasyUEFI.shtml
rem Browser / Brave - https://brave.com - Great for Google/Youtube only
rem Browser / LibreWolf - https://librewolf.net - Great for privacy, like for Facebook
rem Browser / TOR - https://www.torproject.org - Set Settings to Safest to disable all javascripts for max privacy/security!
rem Cloud Backup / IceDrive - https://icedrive.net/plans
rem Cloud Backup / IDrive - https://www.idrive.com/pricing
rem Cloud Backup / PolarBackup - https://www.polarbackup.com/#pricing
rem Compact/Compress Files / Compact GUI - https://github.com/ImminentFate/CompactGUI
rem Computer Management / NirLauncher - https://launcher.nirsoft.net
rem CPU Info / CPU-Z - https://www.cpuid.com/softwares/cpu-z.html
rem CPU Test / Prime95 - https://www.mersenne.org/download
rem Data Recovery / EaseUS Data Recovery Wizard - https://www.easeus.com/datarecoverywizard/free-data-recovery-software.htm
rem Directx 9.0 Runtimes / DirectX Redistributable June 2010 - https://www.softpedia.com/get/System/OS-Enhancements/DirectX-9.0c-Redistributable.shtml
rem Disk Info / CrystalDiskInfo - https://crystalmark.info/en/software/crystaldiskinfo
rem Disk Scan / HDDScan - https://hddscan.com
rem Disk Space Usage / WizTree - https://wiztreefree.com
rem Disk Surface Test / Macrorit Disk Scanner - https://macrorit.com/disk-surface-test/disk-surface-test.html
rem DVD to MKV / MakeMKV Beta - https://www.makemkv.com/download / Key - https://www.makemkv.com/forum2/viewtopic.php?f=5&t=1053
rem eMail / SimpleLogin - https://simplelogin.io/pricing
rem eMail Client / POP Peeper - https://www.esumsoft.com/products/pop-peeper
rem eMail Client / Mailbird - https://www.getmailbird.com
rem eMail Client / POP Peeper - https://www.esumsoft.com/products/pop-peeper
rem File Archiver / NanaZip - https://www.microsoft.com/en-us/p/nanazip/9n8g7tscl18r?activetab=pivot:overviewtab
rem Folder View Globally Set / WinSetView - https://github.com/LesFerch/WinSetView
rem GPU Info / GPU-Z - https://www.techpowerup.com/gpuz
rem GPU Test / Furmark - https://geeks3d.com/furmark
rem Hardware Information / HWiNFO - https://www.hwinfo.com/download.php
rem Hardware Monitor / HWMonitor - https://www.cpuid.com/softwares/hwmonitor.html
rem Image Viewer / XnView - https://www.xnview.com/en/xnview/#downloads
rem Media Player / MPC-BE - https://sourceforge.net/projects/mpcbe
rem Monitor Test / https://www.testufo.com
rem NET 3.5 Feature Installer for Windows 10 x86/x64 - https://github.com/abbodi1406/dotNetFx35W10/releases
rem Network Optimization / TCP Optimizer - https://www.speedguide.net/downloads.php
rem Network Settings Manager / NetSetMan - https://www.netsetman.com/en/freeware
rem Notepad / Notepad3 - https://www.rizonesoft.com/downloads/notepad3
rem Office Suite / LibreOffice - https://www.libreoffice.org
rem Partition Manager / Macrorit Partition Expert - https://macrorit.com/partition-magic-manager/free-edition.html
rem Password Generator / Strong Password Generator - https://apps.microsoft.com/store/detail/strong-password-generator/9NNKGKL4V8HV?hl=en-us&gl=us
rem Password Manager (Offline) / KeePass Professional Edition - https://keepass.info/download.html
rem Password Manager (Online) / Bitwarden - https://bitwarden.com
rem PDF Editor / FreePDF - https://www.getfreepdf.com
rem PDF Viewer / Sumatra PDF - https://www.sumatrapdfreader.org/free-pdf-reader.html
rem Performance / LatencyMon - https://www.resplendence.com/latencymon
rem Performance / HoneCtrl - https://github.com/auraside/HoneCtrl/releases
rem Performance / Process Lasso - https://bitsum.com
rem Performance / WhySoSlow - https://www.resplendence.com/whysoslow
rem Performance / Windows System Timer Tool - https://vvvv.org/contribution/windows-system-timer-tool
rem Permissions / Reset permissions/Take Ownership - http://lallouslab.net/2013/08/26/resetting-ntfs-files-permission-in-windows-graphical-utility/
rem Process Monitor / Process Monitor - https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
rem Radio / Audials Play - https://apps.microsoft.com/store/detail/audials-play-radio-music-tv-podcasts/9PGFN1FJM5TL?hl=en-us&gl=us
rem RAM Fix / Intelligent standby list cleaner (+Timer Resolution) - https://www.wagnardsoft.com/content/intelligent-standby-list-cleaner-v1000-released
rem RAM Free (Memory Leak) / Mem Reduct - https://www.henrypp.org/product/memreduct
rem RAM Free (Memory Leak) / Wise Memory Optimizer - https://www.wisecleaner.com/wise-memory-optimizer.html
rem RAM Disk / ImDisk Toolkit (Unlimited/Unsigned) - https://sourceforge.net/projects/imdisk-toolkit
rem RAM Test / Memtest (run one process per each 2GB) - https://hcidesign.com/memtest
rem Remote Support / TeamViewer - https://www.teamviewer.com/en/download/windows
rem Remove Locked File/Folder / ThisIsMyFile - https://www.softwareok.com/?seite=Freeware/ThisIsMyFile
rem Search / UltraSearch - https://www.jam-software.com/ultrasearch_free
rem Startup Manager / Autoruns - https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
rem Streaming / XSplit - https://www.xsplit.com
rem System Imaging / Hasleo Backup Suite - https://www.easyuefi.com/backup-software/backup-suite-free.html
rem System Restore / Reboot Restore Rx - https://horizondatasys.com/reboot-restore-rx-freeware
rem Task Manager / System Informer - https://www.systeminformer.com/canary
rem Taskbar Overall / ExplorerPatcher - https://github.com/valinet/ExplorerPatcher
rem Taskbar Translucent / TranslucentTB - https://www.microsoft.com/en-us/p/translucenttb/9pf4kz2vn4w9?activetab=pivot:overviewtab
rem Uninstaller / HiBit Uninstaller - https://hibitsoft.ir - https://www.techsupportalert.com/best-free-program-un-installer.htm
rem Visual C++ / AIO Repack - https://github.com/abbodi1406/vcredist/releases
rem Visual C++ / Latest Visual C++ Downloads - https://support.microsoft.com/en-au/help/2977003/the-latest-supported-visual-c-downloads
rem VM Android / BlueStacks - https://www.bluestacks.com
rem VPN / Proton VPN - https://protonvpn.com
rem Wallpaper / Lively Wallpaper - https://apps.microsoft.com/store/detail/lively-wallpaper/9NTM2QC6QWS7?hl=en-us&gl=us
rem Wallpaper / Rainmeter - https://www.rainmeter.net
rem Wallpaper / Wallpaper Engine - https://store.steampowered.com/app/431960
rem Windows Tweaks / Ultimate Windows Tweaker - https://www.thewindowsclub.com/ultimate-windows-tweaker-5-for-windows-11
rem Windows Tweaks / Winaero Tweaker - https://winaero.com/winaero-tweaker


rem ============= Remove various files, folders, startup entries and policies ==============


rem Take ownership of Desktop
takeown /s %computername% /u %username% /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /s %computername% /u %username% /f "Z:\Desktop" /r /d y
icacls "Z:\Desktop" /inheritance:r
icacls "Z:\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

rem Flush DNS Cache
ipconfig /flushdns

rem Remove default user
net user defaultuser1 /delete
net user defaultuser100000 /delete

rem Remove random files/folders
rem del "%AppData%\Microsoft\Windows\Recent\*" /s /f /q
del "%SystemDrive%\AMFTrace.log" /s /f /q
del "%WINDIR%\System32\sru\*" /s /f /q
rd "C:\Users\Tairi\3D Objects" /s /q
rd "C:\Users\Tairi\Favorites" /s /q
rd "C:\Users\Tairi\Links" /s /q
rd "C:\Users\Tairi\Music" /s /q
rd "C:\Users\Tairi\OneDrive" /s /q
rd "C:\Users\Tairi\Searches" /s /q
rd "D:\OneDriveTemp" /s /q
rd "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\HiBitUninstaller\Uninstaller\Backup" /s /q
rd "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\HiBitUninstaller\Uninstaller\Reports" /s /q
rd "%AppData%\AMD" /s /q
rd "%AppData%\ArtifexMundi\SparkPromo" /s /q
rd "%LocalAppData%\Microsoft\Internet Explorer" /s /q
rd "%LocalAppData%\Microsoft\Windows\AppCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\History" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCookies" /s /q
rd "%LocalAppData%\Microsoft\Windows\WebCache" /s /q
rd "%LocalAppData%\SquirrelTemp" /s /q
rd "%LocalAppData%\Steam\htmlcache" /s /q
rd "%LocalAppData%\Temp" /s /q
rd "%ProgramData%\Microsoft\Diagnosis" /s /q
rd "%ProgramData%\Microsoft\DiagnosticLogCSP" /s /q
rd "%ProgramData%\Microsoft\Network" /s /q
rd "%ProgramData%\Microsoft\Search" /s /q
rd "%ProgramData%\Microsoft\SmsRouter" /s /q
rd "%ProgramData%\Microsoft\Windows Defender\Definition Updates" /s /q
rd "%SystemDrive%\AMD" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
rd "%SystemDrive%\PerfLogs" /s /q
rd "%SystemDrive%\Recovery" /s /q
rd "%WinDir%\System32\GroupPolicy" /s /q
rd "%WinDir%\System32\GroupPolicyUsers" /s /q
gpupdate /force

rem Remove/Rebuild Font Cache
del "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*FontCache*"/s /f /q
del "%WinDir%\System32\FNTCACHE.DAT" /s /f /q

rem Remove default Windows Powershell (to restore run "sfc /scannow") - Removing PS will prevent a complete uninstall of store/UWP apps
rem Restrict PS and install the latest version instead - pwsh
rem winget install Microsoft.PowerShell
rem https://thehackernews.com/2023/09/cybercriminals-using-powershell-to.html?m=1
rem https://www.bleepingcomputer.com/news/security/as-microsoft-blocks-office-macros-hackers-find-new-attack-vectors
rem https://www.bleepingcomputer.com/news/security/nsa-shares-tips-on-securing-windows-devices-with-powershell
rem taskkill /im PowerShell.exe /f
rem taskkill /im PowerShell_ISE.exe /f
rem taskkill /im pwsh.exe /f
rem takeown /s %computername% /u %username% /f "%ProgramFiles%\WindowsPowerShell" /r /d y
rem icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rem rd "%ProgramFiles%\WindowsPowerShell" /s /q
rem takeown /s %computername% /u %username% /f "%ProgramFiles(x86)%\WindowsPowerShell" /r /d y
rem icacls "%ProgramFiles(x86)%\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rem rd "%ProgramFiles(x86)%\WindowsPowerShell" /s /q
rem takeown /s %computername% /u %username% /f "%WinDir%\System32\WindowsPowerShell" /r /d y
rem icacls "%WinDir%\System32\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rem rd "%WinDir%\System32\WindowsPowerShell" /s /q
rem takeown /s %computername% /u %username% /f "%WinDir%\SysWOW64\WindowsPowerShell" /r /d y
rem icacls "%WinDir%\SysWOW64\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rem rd "%WinDir%\SysWOW64\WindowsPowerShell" /s /q

rem Remove Startup Folders
takeown /s %computername% /u %username% /f "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
icacls "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" /grant:r %username%:(OI)(CI)F /t /l /q /c
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\*" /s /f /q
del "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\*" /s /f /q

rem Remove random reg keys (Startup/Privacy/Policies/Malware related)
rem reg delete "HKCU\Software\Classes\ms-settings\shell\open" /f
reg delete "HKCU\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKCU\Software\Policies" /f
reg delete "HKLM\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKLM\Software\Microsoft\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Policies" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\WOW6432Node\Policies" /f
reg delete "HKLM\System\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f
reg delete "HKLM\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
reg delete "HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
reg delete "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f


rem =========================== Restore essential startup entries ==========================


rem Run bcdedit command to check for the current status / Yes = True / No = False
rem https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
rem https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4/edit
bcdedit /deletevalue safeboot
bcdedit /deletevalue safebootalternateshell
bcdedit /deletevalue removememory
bcdedit /deletevalue truncatememory
bcdedit /deletevalue useplatformclock
bcdedit /set hypervisorlaunchtype off
bcdedit /set flightsigning off
bcdedit /set {bootmgr} displaybootmenu no
bcdedit /set {bootmgr} flightsigning off
bcdedit /set advancedoptions false
bcdedit /set bootems no
bcdedit /set bootmenupolicy standard
bcdedit /set bootstatuspolicy IgnoreAllFailures
bcdedit /set bootux disabled
bcdedit /set disabledynamictick yes
bcdedit /set lastknowngood yes
bcdedit /set recoveryenabled no
bcdedit /set quietboot yes
bcdedit /set useplatformtick yes
bcdedit /set vsmlaunchtype off
bcdedit /set vm no

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Mailbird" /t REG_SZ /d "C:\Program Files\Mailbird\Mailbird.exe startup" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /t REG_SZ /d "C:\Program Files\Microsoft OneDrive\OneDrive.exe /background" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Steam" /t REG_SZ /d "D:\Steam\steam.exe -silent"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "System Informer" /t REG_SZ /d "C:\Program Files\SystemInformer\SystemInformer.exe -hide" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe," /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /t REG_MULTI_SZ /d "" /f


rem =================================== Software Setup =====================================

rem Audials
taskkill /im AudialsNotifier.exe /f
del "%ProgramFiles%\Audials\Audials 2025\AudialsNotifier.exe" /s /f /q

rem Gihosoft TubeGet
reg add "HKCU\Software\Gihosoft\TubeGet" /v "DefaultOutputFolder" /t REG_SZ /d "Z:/Desktop" /f
reg add "HKCU\Software\Gihosoft\TubeGet" /v "DownloadTempFolder" /t REG_SZ /d "Z:/TEMP/Gihosoft/temp" /f

rem Notepad
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosDX" /t REG_DWORD /d "1934" /f
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosDY" /t REG_DWORD /d "651" /f
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosX" /t REG_DWORD /d "4294967289" /f
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosY" /t REG_DWORD /d "436" /f

rem Regedit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /v "View" /t REG_BINARY /d "2c0000000000000001000000fffffffffffffffffffffffffffffffff7ffffff1c020000850700003e0400002f01000027010000780000002502000003000000" /f

rem TruckersMP
rem takeown /s %computername% /u %username% /f "%ProgramData%\TruckersMP" /r /d y
takeown /f "%ProgramData%\TruckersMP" /a
reg add "HKLM\Software\TruckersMP" /v "InstallDir" /t REG_SZ /d "D:\TruckersMP Launcher" /f
reg add "HKLM\Software\TruckersMP" /v "InstallLocationETS2" /t REG_SZ /d "D:\Steam\steamapps\common\Euro Truck Simulator 2" /f

rem XnView
reg add "HKCU\Software\XnView" /v "UseRegistry" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Browser" /v "ShowToolTips" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Browser" /v "StartupDirectory" /t "REG_SZ" /d "Z:\Desktop" /f
reg add "HKCU\Software\XnView\Browser" /v "StartupIn" /t "REG_DWORD" /d "2" /f
reg add "HKCU\Software\XnView\Capture" /v "Delay" /t "REG_DWORD" /d "2" /f
reg add "HKCU\Software\XnView\Capture" /v "Directory" /t "REG_SZ" /d "Z:\Desktop" /f
reg add "HKCU\Software\XnView\Capture" /v "HotKey" /t "REG_DWORD" /d "9" /f
reg add "HKCU\Software\XnView\Capture" /v "IncludeCursor" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Capture" /v "Method" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Capture" /v "Multiple" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Capture" /v "SaveIntoFile" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Start" /v "MaximizeXnviewAtStartup" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Start" /v "OnlyOneInstance" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Start" /v "PathSave" /t "REG_SZ" /d "Z:\Desktop" /f
reg add "HKCU\Software\XnView\Start" /v "SavePosition" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Start" /v "ShowSaveDlg" /t "REG_DWORD" /d "0" /f


rem =========================== Windows Defender Security Centre ===========================
rem -------------------------------- App & browser control ---------------------------------

rem Off - Disable Windows SmartScreen / On - Enable Windows SmartScreen 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f

rem 0 - Disable SmartScreen Filter in Microsoft Edge / 1 - Enable
reg add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f

rem 0 - Disable SmartScreen PUA in Microsoft Edge / 1 - Enable
reg add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d "0" /f

rem 0 - Disable Windows SmartScreen for Windows Store Apps / 1 - Enable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f

rem ________________________________________________________________________________________
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t "REG_DWORD" /d "0" /f

rem 1 - Enable Microsoft Defender SmartScreen DNS requests
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenDnsRequestsEnabled" /t REG_DWORD /d "0" /f

rem Remove Smartscreen (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
del "%WinDir%\System32\smartscreen.exe" /s /f /q


rem =========================== Windows Defender Security Center ===========================
rem ----------------------------- Device performance & health ------------------------------

rem ________________________________________________________________________________________
rem Specifies how the System responds when a user tries to install device driver files that are not digitally signed / 00 - Ignore / 01 - Warn / 02 - Block
reg add "HKLM\Software\Microsoft\Driver Signing" /v "Policy" /t REG_BINARY /d "01" /f

rem Prevent device metadata retrieval from the Internet / Do not automatically download manufacturers’ apps and custom icons available for your devices
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f 
rem sc config DsmSvc start= disabled

rem Do you want Windows to download driver Software / 0 - Never / 1 - Allways / 2 - Install driver Software, if it is not found on my computer
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f

rem Specify search order for device driver source locations 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d "0" /f

rem 1 - Disable driver updates in Windows Update
rem reg add "HKLM\Software\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
rem reg add "HKLM\Software\Microsoft\PolicyManager\default\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
rem reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
rem reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f

rem Avoid the driver signing enforcement for EV cert / SHA256 Microsoft Windows signed drivers which is further enforced via Secure Boot
rem reg add "HKLM\System\ControlSet001\Control\CI\Policy" /v "UpgradedSystem" /t REG_DWORD /d "1" /f


rem =========================== Windows Defender Security Center ===========================
rem ---------------------------- Firewall & network protection -----------------------------

rem Enable Windows Firewall / AllProfiles / CurrentProfile / DomainProfile / PrivateProfile / PublicProfile
rem https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771920(v=ws.10)
netsh advfirewall set allprofiles state on

rem Block all inbound network traffic and all outbound except allowed apps
netsh advfirewall set DomainProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PrivateProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PublicProfile firewallpolicy blockinboundalways,allowoutbound

rem Remove All Windows Firewall Rules
netsh advfirewall firewall delete rule name=all
rem reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
rem reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f
rem reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedInterfaces" /f
rem reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices" /f

rem Windows Firewall Block Rules
rem https://www.bleepingcomputer.com/news/security/new-windows-pingback-malware-uses-icmp-for-covert-communication
netsh advfirewall firewall add rule name="TCP Block" dir=out action=block protocol=TCP remoteport=1-42,44-79,81-442,444-586,588-852,854-992,994-1024
netsh advfirewall firewall add rule name="UDP Block" dir=out action=block protocol=UDP remoteport=1-122,124-442,444-1024

netsh advfirewall firewall add rule name="Brave TCP" dir=out action=block protocol=TCP remoteport=1-442,444-5227,5229-65535 program="%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"
netsh advfirewall firewall add rule name="Brave UDP" dir=out action=block protocol=UDP remoteport=1-442,444-65535 program="%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"
netsh advfirewall firewall add rule name="Edge TCP" dir=out action=block protocol=TCP remoteport=1-442,444-65535 program="%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
netsh advfirewall firewall add rule name="Edge UDP" dir=out action=block protocol=UDP program="%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
netsh advfirewall firewall add rule name="LibreWolf TCP" dir=out action=block protocol=TCP remoteport=1-442,444-65535 program="%ProgramFiles%\LibreWolf\librewolf.exe"
netsh advfirewall firewall add rule name="LibreWolf UDP" dir=out action=block protocol=UDP program="%ProgramFiles%\LibreWolf\librewolf.exe"
netsh advfirewall firewall add rule name="OneDrive TCP" dir=out action=block protocol=TCP remoteport=1-442,444-65535 program="%ProgramFiles%\Microsoft OneDrive\OneDrive.exe"
netsh advfirewall firewall add rule name="IceDrive TCP" dir=out action=block protocol=TCP remoteport=1-442,444-65535 program="%LocalAppData%\Temp\IcedrivePortable\Icedrive.exe"

rem Windows Firewall Allow Rules
rem netsh advfirewall firewall add rule name="COD MW3 TCP" dir=out action=allow protocol=TCP remoteport=3074,27014-27050 program="D:\steam\steamapps\common\call of duty modern warfare 3\iw5sp.exe"
rem netsh advfirewall firewall add rule name="COD MW3 UDP" dir=out action=allow protocol=UDP remoteport=3074,27000-27060 program="D:\steam\steamapps\common\call of duty modern warfare 3\iw5sp.exe"
rem netsh advfirewall firewall add rule name="Consent TCP" dir=out action=allow protocol=TCP remoteport=80 program="C:\windows\system32\consent.exe"
rem netsh advfirewall firewall add rule name="Creative.sbcommand TCP" dir=out action=allow protocol=TCP remoteport=80 program="%ProgramFiles(x86)%\creative\sound blaster command\creative.sbcommand.exe"
rem netsh advfirewall firewall add rule name="Edge TCP Router" dir=out action=allow protocol=TCP remoteip=192.168.9.1 remoteport=80 program="%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
rem netsh advfirewall firewall add rule name="Genshin Impact TCP" dir=out action=allow protocol=TCP remoteport=80 program="D:\hoyoplay\games\genshin impact game\genshinimpact.exe"
rem netsh advfirewall firewall add rule name="Genshin Impact UDP" dir=out action=allow protocol=UDP remoteport=22101-22102 program="D:\hoyoplay\games\genshin impact game\genshinimpact.exe"
rem netsh advfirewall firewall add rule name="Hasleo TCP" dir=out action=allow protocol=TCP remoteport=80 program="%ProgramFiles%\hasleo\hasleo backup suite\bin\backupmainui.exe"
rem netsh advfirewall firewall add rule name="IPNetInfo TCP" dir=out action=allow protocol=TCP remoteport=43 program="D:\onedrive\soft\windows repair toolbox\downloads\nirlauncher\nirsoft\ipnetinfo.exe"
rem netsh advfirewall firewall add rule name="Lsass TCP" dir=out action=allow protocol=TCP remoteport=80 program="C:\windows\system32\lsass.exe"
rem netsh advfirewall firewall add rule name="RadeonSoftware TCP" dir=out action=allow protocol=TCP remoteport=80 program="C:\program files\amd\cnext\cnext\radeonsoftware.exe"
rem netsh advfirewall firewall add rule name="RuntimeBroker TCP" dir=out action=allow protocol=TCP remoteport=80 program="C:\windows\system32\runtimebroker.exe"
rem netsh advfirewall firewall add rule name="Steam TCP" dir=out action=allow protocol=TCP remoteport=27019 program="D:\steam\steam.exe"
rem netsh advfirewall firewall add rule name="Steam UDP" dir=out action=allow protocol=UDP remoteport=1025-65535 program="D:\steam\steam.exe"
rem netsh advfirewall firewall add rule name="Svchost TCP" dir=out action=allow protocol=TCP remoteport=80 program="C:\windows\system32\svchost.exe"
rem netsh advfirewall firewall add rule name="Svchost TCP DoT" dir=out action=allow protocol=TCP remoteip=9.9.9.9,45.90.28.99,45.90.30.99,149.112.112.112 remoteport=853 program="C:\windows\system32\svchost.exe"
rem netsh advfirewall firewall add rule name="Svchost UDP CDP Sync" dir=out action=allow protocol=UDP remoteport=5050 remoteip=239.255.255.250 program="C:\windows\system32\svchost.exe"
rem netsh advfirewall firewall add rule name="UpdateTime UDP" dir=out action=allow protocol=UDP remoteport=123 program="D:\OneDrive\Soft\Windows Repair Toolbox\downloads\custom tools\added custom tools\updatetime_x64.exe"
rem netsh advfirewall firewall add rule name="WRT TCP" dir=out action=allow protocol=TCP remoteport=80 program="D:\OneDrive\Soft\Windows Repair Toolbox\Windows_Repair_Toolbox.exe"
rem netsh advfirewall firewall add rule name="Xsplit.core TCP" dir=out action=allow protocol=TCP remoteport=80,1935 program="%ProgramFiles%\xsplit\broadcaster\xsplit.core.exe"
rem netsh advfirewall firewall add rule name="Xsplit.core UDP" dir=out action=allow protocol=UDP remoteport=123,5353 program="%ProgramFiles%\xsplit\broadcaster\xsplit.core.exe"
rem netsh advfirewall firewall add rule name="Xsplit.xbcbp TCP" dir=out action=allow protocol=TCP remoteport=80 program="%ProgramFiles%\xsplit\broadcaster\cef3_5060\xsplit.xbcbp.exe"
rem netsh advfirewall firewall add rule name="Xsplit.xbcbp UDP" dir=out action=allow protocol=UDP remoteport=123 program="%ProgramFiles%\xsplit\broadcaster\cef3_5060\xsplit.xbcbp.exe"


rem ================================ Windows Error Reporting ===============================


rem https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings

rem Disable Microsoft Support Diagnostic Tool MSDT
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f

rem Disable System Debugger (Dr. Watson)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f

rem 1 - Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

rem DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f

rem 1 - Disable WER sending second-level data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f

rem 1 - Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

rem 1 - Disable WER logging
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f

schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

rem Windows Error Reporting Service
sc config WerSvc start= disabled


rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem ....................................... General ........................................

rem 2 - Open File Explorer to Quick access / 1 - Open File Explorer to This PC / 3 - Open File Explorer to Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "3" /f

rem Single-click to open an item (point to select)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "2400000017a8000000000000000000000000000001000000130000000000000073000000" /f

rem 2 - Underline icon titles consistent with my browser / 3 - Underline icon titles only when I point at them
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "IconUnderline" /t REG_DWORD /d "2" /f

rem 1 - Show recently used folders
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f

rem 1 - Show frequently folders
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f

rem 1 - Show files from Office.com
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d "0" /f


rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem ........................................ View .........................................

rem Open Explorer - Choose the desired View - View - Options - View - Apply to Folders - OK - Close Explorer ASAP
rem reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
rem reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
rem reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
rem reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
rem reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f
rem reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f
rem reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags" /f
rem reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\BagMRU" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f
rem taskkill /im explorer.exe /f & explorer.exe

rem ________________________________________________________________________________________
rem Remove Network Icon from Navigation Panel / Right in Nav Panel
rem Take Ownership of the Registry key - https://www.youtube.com/watch?v=M1l5ifYKefg
reg add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f

rem Remove Gallery from Navigation Pane in File Explorer
reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

rem Add Desktop under This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "HideIfEnabled" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "HiddenByDefault" /f

rem Add Downloads under This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /v "HideIfEnabled" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /v "HiddenByDefault" /f

rem Add Pictures under This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /v "HideIfEnabled" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /v "HiddenByDefault" /f

rem Remove 3D Folders from This PC
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f

rem Remove Home (Quick access) from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f

rem Remove Documents from This PC
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f

rem Remove Music from This PC
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

rem Remove Videos from This PC
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem .................................. Advanced Settings ...................................

rem 1 - Show hidden files, folders and drives
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f

rem 0 - Show extensions for known file types
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f

rem 0 - Hide protected operating system files 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "1" /f

rem 1 - Launch folder windows in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f

rem 1 - Show Sync Provider Notifications in Windows Explorer (ADs)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f

rem 1 - Use Sharing Wizard
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f

rem Navigation pane - 1 - Expand to open folder
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneExpandToCurrentFolder" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 0 - All of the components of Windows Explorer run a single process / 1 - All instances of Windows Explorer run in one process and the Desktop and Taskbar run in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f

rem Yes - Use Inline AutoComplete in File Explorer and Run Dialog / No
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "No" /f

rem 0 - Do this for all current items checkbox / 1 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d "0" /f

rem 1 - Always show more details in copy dialog
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "0" /f

rem 1 - Disable Previous Version Tab
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoPreviousVersionsPage" /t REG_DWORD /d "1" /f

rem 1 - Display confirmation dialog when deleting files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ConfirmFileDelete" /t REG_DWORD /d "1" /f

rem 1075839525 - Auto arrange icons and Align icons to grid on Desktop / 1075839520 / 1075839521 / 1075839524
reg add "HKCU\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "FFlags" /t REG_DWORD /d "1075839525" /f

rem 1 - Disable Look for an app in the Store (How do you want to open this file)
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f


rem ================================ Windows Optimizations =================================


rem https://prod.support.services.microsoft.com/en-us/windows/options-to-optimize-gaming-performance-in-windows-11-a255f612-2949-4373-a566-ff6f3f474613
rem https://learn.microsoft.com/en-us/shows/seth-juarez/memory-compression-in-windows-10-rtm

rem Determines whether user processes end automatically when the user either logs off or shuts down / 1 - Processes end automatically
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f

rem Specifies the number of times the taskbar button flashes to notify the user that the system has activated a background window
rem If the time elapsed since the last user input exceeds the value of the ForegroundLockTimeout entry, the window will automatically be brought to the foreground (focus)
reg add "HKCU\Control Panel\Desktop" /v "ForegroundFlashCount" /t REG_SZ /d "0" /f

rem ForegroundLockTimeout specifies the time in milliseconds, following user input, during which the system keeps applications from moving into the foreground / 0 - Disabled / 200000 - Default
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f

rem Specifies in milliseconds how long the System waits for user processes to end after the user clicks the End Task command button in Task Manager
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "25000" /f

rem Determines how long the System waits for user processes to end after the user attempts to log off or to shut down
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "25000" /f

rem Determines in milliseconds how long the System waits for services to stop after notifying the service that the System is shutting down
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "25000" /f

rem Determines in milliseconds the interval from the time the cursor is pointed at a menu until the menu items are displayed
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

rem Remove Windows Mouse Acceleration Curve
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f

rem Mouse Hover Time in milliseconds before Pop-up Display
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f

rem 1 - Disable Windows caching DLL in memory
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f

rem How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f

rem n - Disable Background disk defragmentation / y - enable
reg add "HKLM\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "n" /f

rem 0 - Disable FTH (Fault Tolerant Heap)
reg add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t Reg_DWORD /d "0" /f

rem 0 - Disable Background auto-layout / Disable Optimize Hard Disk when idle
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d "0" /f

rem Disable Automatic Maintenance / Scheduled System Maintenance
reg add "HKLM\Software\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f

rem 0 - Enables 8dot3 name creation for all volumes on the system / 1 - Disables 8dot3 name creation for all volumes on the system / 2 - Sets 8dot3 name creation on a per volume basis / 3 - Disables 8dot3 name creation for all volumes except the system volume
rem fsutil 8dot3name scan c:\
fsutil behavior set disable8dot3 1

rem 1 - Disable Bitlocker and Encrypting File System (EFS)
rem manage-bde -status
reg add "HKLM\System\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d "1" /f
fsutil behavior set disableencryption 1

rem 1 - When listing directories, NTFS does not update the last-access timestamp, and it does not record time stamp updates in the NTFS log
rem fsutil behavior query disablelastaccess
fsutil behavior set disablelastaccess 3

rem 2 - Raise the limit of paged pool memory / 1 - Default
fsutil behavior set memoryusage 2

rem System Guard / 0 - Default / 1 - On / 2 - Off
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d "0" /f

rem 1 - Enable virtualization-based security / run msinfo32 to check
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f

rem Platform Security Level / 1 - Turns on VBS with Secure Boot / 3 - Turns on VBS with Secure Boot and DMA
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f

rem Credential Guard / 0 - Disabled (Default) / 1 - Enabled with UEFI lock / 2 - Enabled without lock
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f

rem 1 - Require UEFI Memory Attributes Table
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f

rem 5 - 5 secs / Delay Chkdsk startup time at OS Boot
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d "5" /f

rem 0 - Drivers and the kernel can be paged to disk as needed / 1 - Drivers and the kernel must remain in physical memory
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f

rem 0/3 - Enable / 3/3 - Disable mitigations for CVE-2017-5715 (Spectre Variant 2) and CVE-2017-5754 (Meltdown)
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f

rem 0 - Establishes a standard size file-system cache of approximately 8 MB / 1 - Establishes a large system cache working set that can expand to physical memory, minus 4 MB, if needed
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f

rem 0 - Disable Prefetch / 1 - Enable Prefetch when the application starts / 2 - Enable Prefetch when the device starts up / 3 - Enable Prefetch when the application or device starts up
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f

rem 0 - Disable SuperFetch / 1 - Enable SuperFetch when the application starts up / 2 - Enable SuperFetch when the device starts up / 3 - Enable SuperFetch when the application or device starts up
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f

rem 0 - Disable It / 1 - Default
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBootTrace" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f

rem 0 - Disable Fast Startup for a Full Shutdown / 1 - Enable Fast Startup (Hybrid Boot) for a Hybrid Shutdown
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

rem Disable Fast Startup (Hybrid Boot) and Disable Hibernation
powercfg -h off

rem https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
rem DiagLog is required by Diagnostic Policy Service (Troubleshooting)
rem EventLog-System/EventLog-Application are required by Windows Events Log Service
rem perfmon
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================


rem rem https://admx.help/?Category=Windows_11_2022
rem https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
rem https://learn.microsoft.com/en-us/windows/client-management/new-in-windows-mdm-enrollment-management#whatsnew11
rem https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider
rem https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines

rem Account Lockout Threshold / 0 - Disabled
net accounts /lockoutthreshold:25

rem Account Lockout Duration / 0 - Locks out the account for good, till Administrator unlocks it
net accounts /lockoutduration:1

rem Reset Account Lockout Counter After Time
net accounts /lockoutwindow:1

rem Unlock Locked Out Account
rem net user tairi /active:yes

rem ________________________________________________________________________________________
rem https://www.bleepingcomputer.com/news/security/microsoft-code-sign-check-bypassed-to-drop-zloader-malware
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f

rem 1808 - Disable the warning The Publisher could not be verified
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f

rem Disable Security warning to unblock the downloaded file
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f

rem 1 - Disable Low Disk Space Alerts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f

rem 1 - Don't run specified exe
rem https://lolbas-project.github.io
rem https://blog.talosintelligence.com/2019/11/hunting-for-lolbins.html
rem https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "1" /t REG_SZ /d "addinprocess.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "2" /t REG_SZ /d "addinprocess32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "3" /t REG_SZ /d "addinutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "4" /t REG_SZ /d "aspnet_compiler.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "5" /t REG_SZ /d "bash.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "6" /t REG_SZ /d "bginfo.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "7" /t REG_SZ /d "bitsadmin.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "8" /t REG_SZ /d "cdb.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "9" /t REG_SZ /d "certutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "10" /t REG_SZ /d "cipher.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "11" /t REG_SZ /d "cscript.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "12" /t REG_SZ /d "csi.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "13" /t REG_SZ /d "dbghost.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "14" /t REG_SZ /d "dnx.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "15" /t REG_SZ /d "dotnet.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "16" /t REG_SZ /d "finger.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "17" /t REG_SZ /d "fsi.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "18" /t REG_SZ /d "fsiAnyCpu.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "19" /t REG_SZ /d "ftp.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "20" /t REG_SZ /d "infdefaultinstall.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "21" /t REG_SZ /d "hh.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "22" /t REG_SZ /d "kd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "23" /t REG_SZ /d "kill.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "24" /t REG_SZ /d "lxrun.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "25" /t REG_SZ /d "msbuild.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "26" /t REG_SZ /d "mshta.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "27" /t REG_SZ /d "msra.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "28" /t REG_SZ /d "nc.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "29" /t REG_SZ /d "nc64.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "30" /t REG_SZ /d "ntkd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "31" /t REG_SZ /d "ntsd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "32" /t REG_SZ /d "powershell_ise.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "33" /t REG_SZ /d "powershellcustomhost.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "34" /t REG_SZ /d "psexec.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "35" /t REG_SZ /d "pwsh.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "36" /t REG_SZ /d "rcsi.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "37" /t REG_SZ /d "regsvr32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "38" /t REG_SZ /d "rundll32.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "39" /t REG_SZ /d "runscripthelper.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "40" /t REG_SZ /d "scrcons.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "41" /t REG_SZ /d "texttransform.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "42" /t REG_SZ /d "visualuiaverifynative.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "43" /t REG_SZ /d "wbemtest.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "44" /t REG_SZ /d "wecutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "45" /t REG_SZ /d "werfault.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "46" /t REG_SZ /d "windbg.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "47" /t REG_SZ /d "winrm.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "48" /t REG_SZ /d "winrs.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "49" /t REG_SZ /d "wmic.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "50" /t REG_SZ /d "wscript.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "51" /t REG_SZ /d "wsl.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "52" /t REG_SZ /d "wslconfig.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "53" /t REG_SZ /d "wslhost.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "54" /t REG_SZ /d "findstr.exe" /f

rem N - Disable Distributed Component Object Model (DCOM) support in Windows / Y - Enable
reg add "HKLM\Software\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f

rem 0 - Disable Microsoft Windows Just-In-Time (JIT) script debugging
reg add "HKCU\Software\Microsoft\Windows Script\Settings" /v "JITDebug" /t REG_DWORD /d "0" /f
reg add "HKU\.Default\Microsoft\Windows Script\Settings" /v "JITDebug" /t REG_DWORD /d "0" /f

rem 1 - When the system detects that the user is downloading an external program that runs as part of the Windows user interface, the system searches for a digital certificate or requests that the user approve the action
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "EnforceShellExtensionSecurity" /t REG_DWORD /d "1" /f

rem Disable Active Desktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v "NoAddingComponents" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v "NoComponents" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDesktop" /t REG_DWORD /d "0" /f

rem Enables or disables the retrieval of online tips and help for the Settings app (ADs)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f

rem 1 - Disable recent documents history
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f

rem 1 - Do not add shares from recently opened documents to the My Network Places folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Norecentdocsnethood" /t REG_DWORD /d "1" /f

rem 0 - Disable configuring the machine at boot-up / 1 - Enable configuring the machine at boot-up / 2 - Enable configuring the machine only if DSC is in pending or current state (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DSCAutomationHostEnabled" /t REG_DWORD /d "0" /f

rem 0 - Disable / 1 - Enable (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableCursorSuppression" /t REG_DWORD /d "0" /f

rem 0 - Disable Administrative Shares
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d "0" /f

rem Disabling PowerShell script execution / Restricting PowerShell to Constrained Language mode
rem https://teamt5.org/en/posts/a-deep-dive-into-powershell-s-constrained-language-mode
rem https://www.thewindowsclub.com/how-to-disable-powershell-windows-10
rem Set-ExecutionPolicy bypass - noprofile
reg add "HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f
reg add "HKLM\Software\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics" /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f
reg add "HKLM\Software\WOW6432Node\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics" /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f
reg add "HKLM\Software\Policies\Microsoft\PowerShellCore" /v "EnableScripts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\PowerShellCore" /v "EnableScripts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t REG_SZ /d "4" /f

rem 1 - The device does not store the user's credentials for automatic sign-in after a Windows Update restart. The users' lock screen apps are not restarted after the system restarts.
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f

rem Determines how many user account entries Windows saves in the logon cache on the local computer.
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f

rem Locky ransomware using VBscript (Visual Basic Script) - https://blog.avast.com/a-closer-look-at-the-locky-ransomware
rem https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows - https://dmcxblue.net/2021/08/30/fileless-malware
rem https://www.ryadel.com/en/disable-windows-script-host-wsh-block-vbs-malware
rem https://www.varonis.com/blog/living-off-the-land-lol-with-microsoft-part-ii-mshta-hta-and-ransomware
rem 0 - Disable Windows Script Host (WSH) (prevents majority of malware from working, especially when removing PowerShell as well, Disable ExecutionPolicy can be easily bypassed)
rem Also disabled via DisallowRun "wscript.exe" and "cscript.exe"
reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "0" /f

rem Disable Customer Experience Improvement (CEIP/SQM - Software Quality Management)
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

rem 0 - Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f

rem 0 - Disable Inventory Collector
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f

rem 0 - Disable Program Compatibility Assistant
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f

rem 1 - Disable Steps Recorder (Steps Recorder keeps a record of steps taken by the user, the data includes user actions such as keyboard input and mouse input user interface data and screen shots)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d "0" /f

rem 1 - Specifies that Windows does not automatically encrypt eDrives
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f

rem Network Connection Status Indicator (NCSI/ping/test) - http://www.msftconnecttest.com/connecttest.txt - needed by DoT to avoid no internet connection
rem https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network#ncsi-active-probes-and-the-network-status-alert
reg add "HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "DisablePassivePolling" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "1" /f

rem Disable PerfTrack (tracking of responsiveness events)
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f

rem 1 - Disable Recall Snapshots
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f

rem 1000000000000 - Block untrusted fonts and log events / 2000000000000 - Do not block untrusted fonts / 3000000000000 - Log events without blocking untrusted fonts
reg add "HKLM\Software\Policies\Microsoft\Windows NT\MitigationOptions" /v "MitigationOptions_FontBocking" /t REG_SZ /d "1000000000000" /f

rem 1 - Enable Shutdown Event Tracker / 0 - Disable (Default)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonUI" /t REG_DWORD /d "0" /f

rem 1 - Do not allow storage of passwords and credentials for network authentication in the Credential Manager
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d "1" /f

rem Restrict Delegation of Credentials
rem https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d "1" /f

rem 1 - Network access: Let Everyone permissions apply to anonymous users
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "everyoneincludeanonymous" /t REG_DWORD /d "0" /f

rem https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPLBoot" /t REG_DWORD /d "2" /f

rem Digest Security Provider is disabled by default, but malware can enable it to recover the plain text passwords from the system’s memory (+CachedLogonsCount/+DisableDomainCreds/+DisableAutomaticRestartSignOn)
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f

rem The system registry is no longer backed up to the RegBack folder starting in Windows 10 version 1803
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d "1" /f

rem No-one will be a member of the built-in group, although it will still be visible in the Object Picker / 1 - all users logging on to a session on the server will be made a member of the TERMINAL SERVER USER group
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "TSUserEnabled" /t REG_DWORD /d "0" /f

rem Disable SMB 1.0/2.0
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------

rem https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-stable-channel
rem https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies
rem https://www.microsoft.com/en-us/download/details.aspx?id=55319
rem rem https://admx.help/?Category=EdgeChromium
rem edge://policy

rem reg delete "HKCU\Software\Policies\Microsoft\Edge" /f
rem reg delete "HKLM\Software\Policies\Microsoft\Edge" /f

rem ________________________________________________________________________________________
rem 1 - Allow users to access the games menu
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowGamesMenu" /t REG_DWORD /d "0" /f

rem 1 - Allow the audio sandbox to run
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AudioSandboxEnabled" /t REG_DWORD /d "1" /f

rem 1 - Compose is enabled for writing on the web
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ComposeInlineEnabled" /t REG_DWORD /d "0" /f

rem 1 - AllowJavaScriptJit / 2 - BlockJavaScriptJit (Do not allow any site to run JavaScript JIT)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultJavaScriptJitSetting" /t REG_DWORD /d "0" /f

rem 1 - Allow users to open files using the DirectInvoke protocol
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DirectInvokeEnabled" /t REG_DWORD /d "0" /f

rem 1 - Disable taking screenshots
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DisableScreenshots" /t REG_DWORD /d "1" /f

rem 1 - DNS interception checks enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DNSInterceptionChecksEnabled" /t REG_DWORD /d "0" /f

rem 1 - Drop lets users send messages or files to themselves
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeEDropEnabled" /t REG_DWORD /d "0" /f

rem 1 - Microsoft Edge will attempt to connect to the Microsoft Edge management service to download and apply policy assigned to the Azure AD account of the user
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeManagementEnabled" /t REG_DWORD /d "0" /f

rem 1 - Captures the searches user does on third party search providers
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "Edge3PSerpTelemetryEnabled" /t REG_DWORD /d "0" /f

rem 1 - If you enable this policy, users will be able to access the Microsoft Edge Workspaces feature
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeWorkspacesEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow Google Cast to connect to Cast devices on all IP addresses (Multicast), Edge trying to connect to 239.255.255.250 via UDP port 1900
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EnableMediaRouter" /t REG_DWORD /d "0" /f

rem The Experimentation and Configuration Service is used to deploy Experimentation and Configuration payloads to the client / 0 - RestrictedMode / 1 - ConfigurationsOnlyMode / 2 - FullMode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ExperimentationAndConfigurationServiceControl" /t REG_DWORD /d "0" /f

rem 1 - Allows Microsoft Edge to prompt the user to switch to the appropriate profile when Microsoft Edge detects that a link is a personal or work link
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "GuidedSwitchEnabled" /t REG_DWORD /d "0" /f

rem 1 - Hide restore pages dialog after browser crash
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HideRestoreDialogEnabled" /t REG_DWORD /d "1" /f

rem 1 - Show Hubs Sidebar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f

rem 1 - Enable the Designer for Image Editor feature
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ImageEditorServiceEnabled" /t REG_DWORD /d "0" /f

rem 1 - Enable Picture Dictionary feature within Immersive Reader
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ImmersiveReaderPictureDictionaryEnabled" /t REG_DWORD /d "0" /f

rem 0 -InPrivate mode available / 1 - disabled / 2 - forced
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "InPrivateModeAvailability" /t REG_DWORD /d "1" /f

rem 1 - Allow sites to be reloaded in Internet Explorer mode (IE mode)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "InternetExplorerIntegrationReloadInIEModeAllowed" /t REG_DWORD /d "0" /f

rem 1 - Shows content promoting the Microsoft Edge Insider channels on the About Microsoft Edge settings page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "MicrosoftEdgeInsiderPromotionEnabled" /t REG_DWORD /d "0" /f

rem 1 - Mouse Gesture Enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "MouseGestureEnabled" /t REG_DWORD /d "0" /f

rem 1 - Microsoft Edge built-in PDF reader powered by Adobe Acrobat enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewPDFReaderEnabled" /t REG_DWORD /d "0" /f

rem 1 - Hide the default top sites from the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d "1" /f

rem 1 - Enable QR Code Generator
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "QRCodeGeneratorEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow QUIC protocol
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "QuicAllowed" /t REG_DWORD /d "0" /f

rem 1 - Enable Read Aloud feature in Microsoft Edge
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ReadAloudEnabled" /t REG_DWORD /d "0" /f

rem 1 - Configure Related Matches in Find on Page, the results are processed in a cloud service
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "RelatedMatchesCloudServiceEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow remote debugging
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "RemoteDebuggingAllowed" /t REG_DWORD /d "0" /f

rem 1 - Launches Renderer processes into an App Container for additional security benefits
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "RendererAppContainerEnabled" /t REG_DWORD /d "1" /f

rem 0 - Enable search in sidebar / 1 - DisableSearchInSidebarForKidsMode / 2 - DisableSearchInSidebar 
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchInSidebarEnabled" /t REG_DWORD /d "2" /f

rem 1 - Search for image enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchForImageEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow screen capture
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ScreenCaptureAllowed" /t REG_DWORD /d "0" /f

rem 1 - Allow notifications to set Microsoft Edge as default PDF reader
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowPDFDefaultRecommendationsEnabled" /t REG_DWORD /d "0" /f

rem 1 - The policy can be used to prevent users from opting out of the default behavior of isolating all sites
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "1" /f

rem 1 - Allow Speech Recognition
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SpeechRecognitionEnabled" /t REG_DWORD /d "0" /f

rem 1 - Users can drag a link, or text on a webpage
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SuperDragDropEnabled" /t REG_DWORD /d "0" /f

rem 1 - URL reporting in Edge diagnostic data enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "UrlDiagnosticDataEnabled" /t REG_DWORD /d "0" /f

rem 1 - Edge User Data Profile Location
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "UserDataDir" /t REG_SZ /d "Z:\Edge\User Data" /f

rem 1 - Allow video capture
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "VideoCaptureAllowed" /t REG_DWORD /d "0" /f

rem 1 - Wallet Donation Enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "WalletDonationEnabled" /t REG_DWORD /d "0" /f

rem 1 - DNS-based WPAD optimization (Web Proxy Auto-Discovery)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "WPADQuickCheckEnabled" /t REG_DWORD /d "0" /f

rem 0 - Prevent Desktop Shortcut creation upon install default
reg add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcut{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "RemoveDesktopShortcutDefault" /t REG_DWORD /d "1" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ..................................... Appearances ......................................

rem 0 - Show share button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ConfigureShare" /t REG_DWORD /d "1" /f

rem 1 - Show Collections button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeCollectionsEnabled" /t REG_DWORD /d "0" /f

rem 1 - Show favorites bar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "FavoritesBarEnabled" /t REG_DWORD /d "1" /f

rem 1 - The performance detector detects tab performance issues and recommends actions to fix the performance issues
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PerformanceDetectorEnabled" /t REG_DWORD /d "0" /f

rem 1 - Pin browser essentials toolbar button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PinBrowserEssentialsToolbarButton" /t REG_DWORD /d "0" /f

rem 1 - Show mini menu when selecting text
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "QuickSearchShowMiniMenu" /t REG_DWORD /d "0" /f

rem 1 - Always show the Downloads button on the toolbar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowDownloadsToolbarButton" /t REG_DWORD /d "0" /f

rem 1 - Show home button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowHomeButton" /t REG_DWORD /d "0" /f

rem 1 - nable split screen feature
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SplitScreenEnabled" /t REG_DWORD /d "0" /f

rem 1 - Show feedback button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f

rem 1 - Show tab actions menu (Show vertical tabs)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "VerticalTabsAllowed" /t REG_DWORD /d "0" /f

rem 1 - Show web capture button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "WebCaptureEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - Enables background updates to the list of available templates for Collections and other features that use templates
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BackgroundTemplateListUpdatesEnabled" /t REG_DWORD /d "0" /f

rem 1 - Enable the Search bar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchbarAllowed" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem .............................. Cookies and site permissions ............................

rem PDF Documents
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d "1" /f

rem Ads setting for sites with intrusive ads / 1 - Allow ads on all sites / 2 - Block ads on sites with intrusive ads. (Default value)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AdsSettingForIntrusiveAdsSites" /t REG_DWORD /d "1" /f

rem Clipboard / 2 - BlockClipboard / 3 - AskClipboard
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultClipboardSetting" /t REG_DWORD /d "2" /f

rem File Editing / 2 - BlockFileSystemRead / 3 - AskFileSystemRead
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultFileSystemReadGuardSetting" /t REG_DWORD /d "2" /f

rem File Editing / 2 - BlockFileSystemWrite / 3 - AskFileSystemWrite
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultFileSystemWriteGuardSetting" /t REG_DWORD /d "2" /f

rem Location / 1 - AllowGeolocation / 2 - BlockGeolocation / 3 - AskGeolocation
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f

rem Insecure Content / 2 - BlockInsecureContent / 3 - AllowExceptionsInsecureContent
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultInsecureContentSetting" /t REG_DWORD /d "2" /f

rem Notifications / 1 - AllowNotifications / 2 - BlockNotifications / 3 - AskNotifications
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultNotificationsSetting" /t REG_DWORD /d "2" /f

rem Motion or light sensors / 1 - AllowSensors / 2 - BlockSensors
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultSensorsSetting" /t REG_DWORD /d "2" /f

rem Serial ports / 2 - BlockSerial / 3 - AskSerial 
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultSerialGuardSetting" /t REG_DWORD /d "2" /f

rem USB Devices / 2 - BlockWebUsb / 3 - AskWebUsb
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "2" /f

rem ________________________________________________________________________________________
rem 1 - Allow audio capture
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AudioCaptureAllowed" /t REG_DWORD /d "0" /f

rem Bluetooth / 2 - BlockWebBluetooth / 3 - AskWebBluetooth
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d "2" /f

rem Access to HID devices via the WebHID API / 2 - BlockWebHid / 3 - AskWebHid
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultWebHidGuardSetting" /t REG_DWORD /d "2" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ...................................... Downloads .......................................

rem Set download directory
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DownloadDirectory" /t REG_SZ /d "Z:\Desktop" /f

rem 1 - Ask me what to do with each download (Ignored when download directory is set)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PromptForDownloadLocation" /t REG_DWORD /d "1" /f

rem 1 - Open Office files in the browser
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "QuickViewOfficeFilesEnabled" /t REG_DWORD /d "0" /f

rem 1 - Enable insecure download warnings
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowDownloadsInsecureWarningsEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ..................................... Extensions .......................................

rem 1 - Allow extensions from other stores
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ControlDefaultStateOfAllowExtensionFromOtherStoresSettingEnabled" /t REG_DWORD /d "0" /f

rem 1 - DeveloperToolsAllowed / 2 - DeveloperToolsDisallowed (Don't allow using the developer tools)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DeveloperToolsAvailability" /t REG_DWORD /d "2" /f

rem ________________________________________________________________________________________
rem 1 - Blocks external extensions from being installed
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BlockExternalExtensions" /t REG_DWORD /d "1" /f

rem 1 - EnabledForBrowser (Prevent the browser process from creating dynamic code) / 0 - Default
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ExtensionDeveloperModeSettings" /t REG_DWORD /d "1" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ...................................... Languages .......................................

rem 1 - Enable spellcheck
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SpellcheckEnabled" /t REG_DWORD /d "1" /f

rem 1 - Offer to translate pages that aren't in a language I read
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TranslateEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - The Microsoft Editor service provides enhanced spell and grammar checking for editable text fields on web pages
rem https://www.bleepingcomputer.com/news/security/google-microsoft-can-get-your-passwords-via-web-browsers-spellcheck
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "MicrosoftEditorProofingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "MicrosoftEditorSynonymsEnabled" /t REG_DWORD /d "0" /f

rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ..................................... New tab page .....................................

rem Page Layout / 1 - DisableImageOfTheDay / 2 -  DisableCustomImage / 3 - DisableAll
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageAllowedBackgroundTypes" /t REG_DWORD /d "1" /f

rem 1 - Allow Microsoft News content on the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageContentEnabled" /t REG_DWORD /d "0" /f

rem 1 - Preload the new tab page for a faster experience
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPagePrerenderEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - Hide the default top sites from the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d "1" /f

rem 1 - Allow quick links on the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageQuickLinksEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ....................................... Personal .......................................

rem 1 - Add profile
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BrowserAddProfileEnabled" /t REG_DWORD /d "0" /f

rem 1 - Browse as guest
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BrowserGuestModeEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow users to configure Family safety and Kids Mode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "FamilySafetySettingsEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ............................ Privacy, search, and services .............................

rem 1 - Suggest similar sites when a website can't be found
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f

rem Automatically switch to more secure connections with Automatic HTTPS / 0 - Disabled / 1 - Switch to supported domains / 2 - Always
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AutomaticHttpsDefault" /t REG_DWORD /d "2" /f

rem 1 - Clear browsing data when Microsoft Edge closes
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ClearBrowsingDataOnExit" /t REG_DWORD /d "1" /f

rem 1 - Clear cached images and files when Microsoft Edge closes
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ClearCachedImagesAndFilesOnExit" /t REG_DWORD /d "1" /f

rem edge://settings/content/cookies/siteData
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "0" /t REG_SZ /d "[*.]ntp.msn.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "1" /t REG_SZ /d "[*.]account.samsung.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "2" /t REG_SZ /d "[*.]alza.sk" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "3" /t REG_SZ /d "[*.]netflix.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "4" /t REG_SZ /d "[*.]deviantart.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "5" /t REG_SZ /d "[*.]discord.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "6" /t REG_SZ /d "[*.]duckduckgo.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "7" /t REG_SZ /d "[*.]elevenforum.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "8" /t REG_SZ /d "[*.]tesco.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "9" /t REG_SZ /d "[*.]fio.sk" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "10" /t REG_SZ /d "[*.]forums.mydigitallife.net" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "11" /t REG_SZ /d "[*.]github.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "12" /t REG_SZ /d "[*.]heureka.sk" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "13" /t REG_SZ /d "[*.]hoyolab.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "14" /t REG_SZ /d "[*.]hoyoverse.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "15" /t REG_SZ /d "[*.]imdb.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "16" /t REG_SZ /d "[*.]isthereanydeal.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "17" /t REG_SZ /d "[*.]itesco.sk" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "18" /t REG_SZ /d "[*.]malwaretips.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "19" /t REG_SZ /d "[*.]mlpforums.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "20" /t REG_SZ /d "[*.]myanimelist.net" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "21" /t REG_SZ /d "[*.]nextdns.io" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "22" /t REG_SZ /d "[*.]mbank.sk" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "23" /t REG_SZ /d "[*.]pcforum.sk" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "24" /t REG_SZ /d "[*.]poniverse.net" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "25" /t REG_SZ /d "[*.]primevtc.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "26" /t REG_SZ /d "[*.]roextended.ro" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "27" /t REG_SZ /d "[*.]softpedia.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "28" /t REG_SZ /d "[*.]steamcommunity.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "29" /t REG_SZ /d "[*.]steampowered.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "30" /t REG_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "31" /t REG_SZ /d "[*.]truckersmp.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "32" /t REG_SZ /d "[*.]twitch.tv" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "33" /t REG_SZ /d "[*.]vk.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "34" /t REG_SZ /d "[*.]wilderssecurity.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "35" /t REG_SZ /d "[*.]goodreads.com" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SaveCookiesOnExit" /v "36" /t REG_SZ /d "[*.]ce-tescoassets.com" /f

rem Diagnostic Data / 0 - Off / 1 - RequiredData / 2 - OptionalData
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d "0" /f

rem Enhance the security state in Microsoft Edge / 0 - Standard mode / 1 - Balanced mode / 2 - Strict mode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EnhanceSecurityMode" /t REG_DWORD /d "2" /f

rem Search on new tabs uses search box or address bar / redirect - address bar / bing - search box
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageSearchBox" /t REG_SZ /d "redirect" /f

rem 1 - Use a web service to help resolve navigation errors
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f

rem 1 - Show me search and site suggestions using my typed characters
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f

rem 1 - Turn on site safety services to get more info about the sites you visit
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SiteSafetyServicesEnabled" /t REG_DWORD /d "0" /f

rem 1 - Suggest group names when creating a new tab group
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TabServicesEnabled" /t REG_DWORD /d "0" /f

rem Tracking prevention / 0 - Off / 1 - Basic / 2 - Balanced / 3 - Strict
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TrackingPrevention" /t REG_DWORD /d "0" /f

rem 1 - Typosquatting Checker (just sending what you type to MS)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TyposquattingCheckerEnabled" /t REG_DWORD /d "0" /f

rem 1 - Visual search (sending what you are looking at to MS)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "VisualSearchEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem Enable Microsoft Search in Bing suggestions in the address bar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow users to bypass Enhanced Security Mode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EnhanceSecurityModeAllowUserBypass" /t REG_DWORD /d "0" /f

rem Force the default Search engine and Prevent adding custom search engines
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ManagedSearchEngines" /t REG_SZ /d "[{\"allow_search_engine_discovery\":false},{\"is_default\":true,\"name\":\"DuckDuckGo\",\"keyword\":\"duckduckgo.com\",\"search_url\":\"https://duckduckgo.com/?q={searchTerms}\",\"suggest_url\":\"https://www.duckduckgo.com/qbox?query={searchTerms}\",\"image_search_url\":\"https://www.duckduckgo.com/images/detail/search?iss=sbiupload\"}]" /f

rem Allow personalization of ads, Microsoft Edge, search, news and other Microsoft services by sending browsing history, favorites and collections, usage and other browsing data to Microsoft
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f

rem Allow recommendations and promotional notifications from Microsoft Edge
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f

rem Choose whether users can receive customized background images and text, suggestions, notifications, and tips for Microsoft services)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f

rem Use secure DNS (DoH)
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "1" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://security.cloudflare-dns.com/dns-query?" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ...................................... Profiles ........................................

rem 1 - Save and fill personal info
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f

rem 1 - Save and fill payment info
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f

rem Browser sign-in settings / 0 - Disable / 1 - Enable / 2 - Force users to sign-in to use the browser (all profiles)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BrowserSignin" /t REG_DWORD /d "2" /f

rem 1 - Let users compare the prices of a product they are looking at, get coupons or rebates from the website they're on
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f

rem 1 - Forces data synchronization in Microsoft Edge. This policy also prevents the user from turning sync off.
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ForceSync" /t REG_DWORD /d "1" /f

rem If you enable this policy all the specified data types will be included for synchronization
reg add "HKLM\Software\Policies\Microsoft\Edge\ForceSyncTypes" /v "1" /t REG_SZ /d "extensions" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\ForceSyncTypes" /v "2" /t REG_SZ /d "favorites" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\ForceSyncTypes" /v "3" /t REG_SZ /d "settings" /f

rem If you enable this policy all the specified data types will be excluded from synchronization
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "1" /t REG_SZ /d "addressesAndMore" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "2" /t REG_SZ /d "apps" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "3" /t REG_SZ /d "collections" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "4" /t REG_SZ /d "edgeWallet" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "5" /t REG_SZ /d "history" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "6" /t REG_SZ /d "openTabs" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "7" /t REG_SZ /d "passwords" /f

rem 1 - Disable Share Microsoft Edge Browsing Data with other Windows Features
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "LocalBrowserDataShareEnabled" /t REG_DWORD /d "0" /f

rem 1 - Suggest strong passwords
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordGeneratorEnabled" /t REG_DWORD /d "0" /f

rem 1 - Offer to save passwords
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordManagerEnabled" /t REG_DWORD /d "0" /f

rem 1 - Show alerts when passwords are found in an online leak
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordMonitorAllowed" /t REG_DWORD /d "0" /f

rem 1 - Show the "Reveal password" button in password fields
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordRevealEnabled" /t REG_DWORD /d "0" /f

rem Sign in: / 0 - Automatically / 1 - With device password
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PrimaryPasswordSetting" /t REG_DWORD /d "0" /f

rem 1 - Show Microsoft Rewards experience and notifications
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowMicrosoftRewards" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - Single sign-on for work or school sites using this profile enabled
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AADWebSiteSSOUsingThisProfileEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow single sign-on for Microsoft personal sites using this profile
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "MSAWebSiteSSOUsingThisProfileAllowed" /t REG_DWORD /d "0" /f

rem Configure the list of domains where Microsoft Edge should disable the password manager
rem reg add "HKLM\Software\Policies\Microsoft\Edge\PasswordManagerBlocklist" /v "1" /t REG_SZ /d "https://steamcommunity.com" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge\PasswordManagerBlocklist" /v "2" /t REG_SZ /d "https://store.steampowered.com" /f


rem =================================== Windows Policies ===================================
rem ------------------------------------ Microsoft Edge ------------------------------------
rem ................................ System and performance ................................

rem 1 - Continue running background apps when Microsoft Edge is closed
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f

rem Efficiency Mode / 1 - Enables efficiency mode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EfficiencyModeEnabled" /t REG_DWORD /d "0" /f

rem 1 - Use hardware acceleration when available
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f

rem 1 - Save resources with sleeping tabs
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SleepingTabsEnabled" /t REG_DWORD /d "0" /f

rem 1 - Startup boost
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - If ECH is enabled, Microsoft Edge might or might not use ECH depending on server support, the availability of the HTTPS DNS record
rem Enable: DOH + the paramater: --enable-features="EncryptedClientHello" - https://www.cloudflare.com/ssl/encrypted-sni
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EncryptedClientHelloEnabled" /t REG_DWORD /d "1" /f

rem 1 - Enable Gamer Mode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "GamerModeEnabled" /t REG_DWORD /d "0" /f

rem NetworkPrediction / 0 - Always / 1 - WifiOnly / 2 - Never
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NetworkPredictionOptions" /t REG_DWORD /d "2" /f

rem =================================== Windows Policies ===================================
rem --------------------------------- User Account Control ---------------------------------

rem https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd835564(v=ws.10)
rem Reason to set UAC to Always Notify - https://learn.microsoft.com/en-us/previous-versions/technet-magazine/dd822916(v=msdn.10)
rem https://daniels-it-blog.blogspot.com/2020/07/uac-bypass-via-dll-hijacking-and-mock.html
rem https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/
rem There are really only two effectively distinct settings for the UAC slider - https://devblogs.microsoft.com/oldnewthing/20160816-00/?p=94105

rem 0 - Elevate without prompting / 1 - Prompt for credentials on the secure desktop / 2 - Prompt for consent on the secure desktop / 3 - Prompt for credentials / 4 - Prompt for consent / 5 (Default) - Prompt for consent for non-Windows binaries
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f

rem 0 - Automatically deny elevation requests / 1 - Prompt for credentials on the secure desktop / 3 (Default) - Prompt for credentials
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f

rem 2 (Default)
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFullTrustStartupTasks" /t REG_DWORD /d "0" /f

rem Detect application installations and prompt for elevation / 1 - Enabled (default for home) / 0 - Disabled (default for enterprise)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f

rem Run all administrators in Admin Approval Mode / 0 - Disabled (UAC) / 1 - Enabled (UAC)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f

rem Only elevate UIAccess applications that are installed in secure locations / 0 - Disabled / 1 (Default) - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "1" /f

rem 0 (Default) = Disabled / 1 - Enabled
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUwpStartupTasks" /t REG_DWORD /d "0" /f

rem Allow UIAccess applications to prompt for elevation without using the secure desktop / 0 (Default) = Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f

rem https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/932a34b5-48e7-44c0-b6d2-a57aadef1799
rem 0 - Disabled / 1 - Enabled (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f

rem Admin Approval Mode for the built-in Administrator account / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f

rem Allow UIAccess applications to prompt for elevation without using the secure desktop / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f

rem Enforce cryptographic signatures on any interactive application that requests elevation of privilege / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "1" /f

rem Display highly detailed status messages / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f

rem 1 - Enable command-line auditing
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d "1" /f


rem =============================== Windows Scheduled Tasks ================================


rem UAC Bypass - https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup
rem MsCtfMonitor Task (keylogger) is required to be able to type within Settings and etc

schtasks /DELETE /TN "AMDInstallLauncher" /f
schtasks /DELETE /TN "AMDInstallUEP" /f
schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f
schtasks /DELETE /TN "DUpdaterTask" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "StartAUEP" /f
schtasks /DELETE /TN "StartCN" /f
schtasks /DELETE /TN "StartCNBM" /f
schtasks /DELETE /TN "StartDVR" /f

schtasks /Change /TN "CreateExplorerShellUnelevatedTask" /Enable

schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\SdbinstMergeDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\AppxDeploymentClient\UCPD velocity" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\syncpensettings" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\Network Connectivity Status Indicator\NcsiIdentifyUserProxies" /Disable
schtasks /Change /TN "Microsoft\Windows\PerformanceTrace\RequestTrace" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\PrintJobCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\ThemesSyncedImageDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sustainability\PowerGridForecastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Sustainability\SustainabilityTelemetry" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
schtasks /Change /TN "Microsoft\Windows\WlanSvc\MoProfileManagement" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable


rem ================================== Windows Services ====================================


rem https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/optimize/services
rem https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows
rem https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server

rem Application Information / required by UAC
rem AppX Deployment Service (AppXSVC) / required by Store
rem Background Intelligent Transfer Service / required by Windows Updates / depends on Network List Service (starts even when disabled)
rem Base Filtering Engine / required by Windows Defender Firewall
rem BitLocker Drive Encryption Service / required to be able to access encryption settings and to disable Bitlocker and device encryption
rem CNG Key Isolation / required to login to Windows Insider / Switch to Local Account / Set up PIN / Basically everything Credentials related
rem Connected Devices Platform / required to open Settings - Windows Backup and to sync Edge with android
rem Credential Manager / required to store credentials (check User Accounts - Credential Manager) / required by apps like Windows Mail to store passwords / An administrator has blocked you from running this app
rem Cryptographic Services / required to update certificates for browsers, digital signatures (catroot2)
rem Delivery Optimization / required by Windows Updates
rem DevicesFlow / required to open Settings - Bluetooth and devices 
rem Diagnostic Policy Service / required by Windows Diagnostic (Troubleshooting)
rem DHCP Client / sometimes required by Windows Updates (0x80240022)
rem Display Policy Service / to keep display's settings like a refresh rate
rem Distributed Link Tracking Client / sometimes required to open shortcuts and System apps - "Windows cannot access the specified device, path, or file. You may not have the appropriate permission to access the item"
rem Geolocation Service / required by some Windows Store apps, it can not be enabled when Connected User Experiences and Telemetry is disabled
rem Microsoft Account Sign-in Assistant / required to login to Microsoft Account
rem Network Connections / required to manage old Network Connections
rem Network Connection Broker / required to change Network Settings
rem Network List Service / required by Windows Update and to change Network Settings (when disabled desktop fails to load)
rem Network Location Awareness / required by Windows Update and Windows Defender Firewall
rem Network Store Interface Service / disabling disables Windows Firewall (when disabled Windows might fail to boot - Critical Service Died)
rem Print Spooler / required by printers
rem Radio Management Service / required to display WiFi networks
rem Security Accounts Manager / when disabled, explorer.exe (Desktop) crashes constantly
rem System Guard Runtime Monitor Broker / when disabled Windows might fail to boot - Critical Service Died
rem Storage Service / required to update store apps
rem Text Input Management Service (keeps ctfmon.exe running) / required to be able to login at all
rem User Data services / required to be able to change PIN/password at lockscreen or to login via Microsoft Authenticator
rem Web Account Manager / required to login to Microsoft Account/Store
rem Windows Biometric Service / required by biometric devices like a fingerprint reader
rem Windows Connection Manager / required by WiFi and Data Usage and Windows Update (starts even when disabled)
rem Windows Defender Firewall (Base Filtering Engine/Network Location Awareness) / required by Windows Update and Store Apps (0x80073d0a)
rem Windows Driver Foundation - User-mode Driver Framework / required by some drivers like USB devices
rem Windows Image Acquisition (WIA) / required by scanners
rem Windows Management Instrumentation / required by wmic commands / disabled to prevent some fileless malware
rem Windows Push Notifications User Service / required by Logitech Setpoint to avoid Runtime Error and upon disabling, Windows and network is sluggish

rem AMD Crash Defender Driver
sc config amdfendr start= disabled

rem AMD Crash Defender Driver
sc config amdfendrmgr start= disabled

rem AMD Crash Defender Service
sc config "AMD Crash Defender Service" start= disabled

rem AMD External Events Utility
sc config "AMD External Events Utility" start= disabled

rem AMD Link Controller Emulation
sc config AMDXE start= disabled

rem AMD Provisioning Packages Service
sc config AmdPpkgSvc start= disabled

rem AMD PSP Driver
sc config amdpsp start= disabled

rem AMD Streaming Audio Driver
sc config AMDSAFD start= disabled

rem AMD User Experience Program Data Uploader
sc config "AUEPLauncher" start= disabled

rem AVCTP service
sc config BthAvctpSvc start= disabled

rem BitLocker Drive Encryption Service
sc config BDESVC start= disabled

rem Bluetooth Support Service
sc config bthserv start= disabled

rem Clipboard User Service
sc config cbdhsvc start= disabled

rem Connected User Experiences and Telemetry
sc config DiagTrack start= disabled

rem Contact Data
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f

rem Data Sharing Service
sc config DsSvc start= disabled

rem Data Usage
sc config DusmSvc start= disabled

rem DevQuery Background Discovery Broker
sc config DevQueryBroker start= disabled

rem Device Management Wireless Application Protocol (WAP) Push message Routing Service
sc config dmwappushservice start= disabled

rem DHCP Client
sc config Dhcp start= disabled

rem Display Enhancement Service
sc config DisplayEnhancementService start= disabled

rem Distributed Link Tracking Client
sc config TrkWks start= disabled

rem dLauncherLoopback
sc config dLauncherLoopback start= demand

rem Encrypting File System (EFS)
sc config EFS start= disabled

rem FileSyncHelper (required to open Personal Vault in OneDrive)
sc config FileSyncHelper start= demand

rem Function Discovery Provider Host
sc config fdPHost start= disabled

rem Function Discovery Resource Publication
sc config FDResPub start= disabled

rem Geolocation Service
sc config lfsvc start= disabled

rem Hasleo Backup Suite Image Mount Service
sc config "HasleoImageMountService" start= disabled

rem Hasleo Backup Suite Service
sc config "HasleoBackupSuiteService" start= disabled

rem HV Host Service
sc config HvHost start= disabled

rem IKE and AuthIP IPsec Keying Modules
sc config IKEEXT start= disabled

rem Inventory and Compatibility Appraisal service
sc config InventorySvc start= disabled

rem IP Helper
sc config iphlpsvc start= disabled

rem IPsec Policy Agent
sc config PolicyAgent start= disabled

rem Microsoft (R) Diagnostics Hub Standard Collector Service
sc config diagnosticshub.standardcollector.service start= disabled

rem Network Connections
sc config Netman start= disabled

rem Network Policy Server Management Service
sc config NPSMSvc start= disabled

rem Optimize drives
sc config defragsvc start= disabled

rem Payments and NFC/SE Manager
sc config SEMgrSvc start= disabled

rem Portable Device Enumerator ServicePayments and NFC/SE Manager
sc config WPDBusEnum start= disabled

rem Program Compatibility Assistant Service
sc config PcaSvc start= disabled

rem Print Spooler
sc config Spooler start= disabled

rem Radio Management Service
sc config RmSvc start= disabled

rem Remote Access Connection Manager
sc config RasMan start= disabled

rem Remote Desktop Services
sc config TermService start= disabled

rem Retail Demo
sc config RetailDemo start=disabled

rem Quality Windows Audio Video Experience
sc config QWAVE start=disabled

rem Secure Socket Tunneling Protocol Service
sc config SstpSvc start=disabled

rem Server
sc config LanmanServer start= disabled

rem Shell Hardware Detection
sc config ShellHWDetection start= disabled

rem SSDP Discovery
sc config SSDPSRV start= disabled

rem Superfetch
sc config SysMain start= disabled

rem Sync Host
sc config OneSyncSvc start= disabled

rem TCP/IP NetBIOS Helper
sc config lmhosts start= disabled

rem UserChoice Protection Driver (UCPD) - disable to be able to change reg values for ShellFeedsTaskbarViewMode/IsFeedsAvailable/TaskbarDa/DeviceRegion
sc config ucpd start= disabled

rem WebClient
sc config WebClient start= disabled

rem Web Threat Defense Service (Phishing protection)
sc config webthreatdefsvc start= disabled

rem Web Threat Defense User Service (Phishing protection)
sc config webthreatdefusersvc start= disabled

rem Windows Biometric Service
sc config WbioSrvc start= disabled

rem Windows Connection Manager
sc config Wcmsvc start= disabled

rem Windows Font Cache Service
sc config FontCache start= disabled

rem Windows Image Acquisition (WIA)
sc config StiSvc start= disabled

rem Windows Remote Management (WS-Management)
sc config WinRM start= disabled

rem Windows Search
sc config WSearch start= disabled

rem Windows Time
sc config W32Time start= disabled

rem WinHTTP Web Proxy Auto-Discovery Service
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f

rem Workstation
sc config LanmanWorkstation start= disabled


rem =================================== Windows Settings ===================================
rem ------------------------------------ Accessibility ------------------------------------
rem ....................................... Audio .........................................
rem . . . . . . . . . . . . . . . . . . Sound themes . . . . . . . . . . . . . . . . . . .

rem Delete Windows Default Sounds (Permanently)
reg delete "HKCU\AppEvents\Schemes\Apps" /f

rem When windows detects communications activity / 0 - Mute all other sounds / 1 - Reduce all other by 80% / 2 - Reduce all other by 50% / 3 - Do nothing
reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f

rem 0 - Play Windows Startup sound
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\EditionOverrides" /v "UserSetting_DisableStartupSound" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ------------------------------------ Accessibility ------------------------------------
rem ........................................ Mouse ........................................

rem Mouse Keys / 62 - Disable / 63 - Default
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "62" /f


rem =================================== Windows Settings ===================================
rem ------------------------------------ Accessibility ------------------------------------
rem ...................................... Keyboard .......................................

rem Filter keys / 126 - Disable All / 127 - Default
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "126" /f

rem Sticky keys / 26 - Disable All / 511 - Default
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "26" /f

rem Toggle keys / 58 - Disable All / 63 - Default
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f

rem ________________________________________________________________________________________
rem 1 - Disable Windows Key Hotkeys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWinKeys" /t REG_DWORD /d "1" /f
rem Disable specific Windows Key Hotkeys only (like R = Win+R)
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisabledHotkeys" /t REG_EXPAND_SZ /d "R" /f


rem =================================== Windows Settings ===================================
rem ------------------------------------ Accessibility ------------------------------------
rem ...................................... Keyboard .......................................
rem . . . . . . . . . . . . . . . . . . . . Typing . . . . . . . . . . . . . . . . . . . .


rem 1 - Show text suggestions when typing on the physical keyboard (Privacy)
reg add "HKCU\Software\Microsoft\Input\Settings" /v "EnableHwkbTextPrediction" /t REG_DWORD /d "0" /f

rem Typing insights (Privacy)
reg add "HKCU\Software\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f

rem 1 - Multilingual text suggestions (Privacy)
reg add "HKCU\Software\Microsoft\Input\Settings" /v "MultilingualEnabled" /t REG_DWORD /d "0" /f

rem 1 - Autocorrect misspelled words (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f

rem 1 - Highlight misspelled words (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f

rem Inking & Typing Personalization (Privacy)
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection " /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts " /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy  " /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
reg add "HKCU\Software\Microsoft\Input" /v "IsInputAppPreloadEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Input\Settings" /v "VoiceTypingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem -------------------------------------- Accounts ----------------------------------------
rem ................................... Sing-in options ....................................

rem 1 - Automatically save my restartable apps when I sign out and restart them after I sign in
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "RestartApps" /t REG_DWORD /d "0" /f

rem 2 - For improved security, only allow Windows Hello sign-in for Microsoft accounts on this device / 0 - Off
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" /v "DevicePasswordLessBuildVersion" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Apps ------------------------------------------
rem ................................... Apps & features ....................................

rem Choose where to get apps  - Anywhere / PreferStore / StoreOnly / Recommendations
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AicEnabled" /t REG_SZ /d "Anywhere" /f

rem Share across devices / 0 - Off / 1 - My devices only / 2 - Everyone nearby
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v "EnableAppInstaller" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v "EnableDefaultSource" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v "EnableExperimentalFeatures" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v "EnableMicrosoftStoreSource" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v "EnableMSAppInstallerProtocol" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v "EnableSettings" /t REG_DWORD /d "1" /f

rem Let apps run in the background / 0 - Enabled / 1 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f

rem Let apps run in the background / 1 - Enabled / 0 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

rem Let apps run in the background / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Apps ------------------------------------------
rem .................................. Optional features ...................................

rem DISM /Online /Get-Features /Format:Table
rem Windows Basics


rem =================================== Windows Settings ===================================
rem --------------------------------- Bluetooth & Devices ----------------------------------
rem ...................................... Autoplay .......................................

rem 0 - Use Autoplay for all media and devices
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f 

rem ________________________________________________________________________________________
rem Disable AutoPlay and AutoRun
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f


rem =================================== Windows Settings ===================================
rem --------------------------------- Bluetooth & Devices ----------------------------------
rem ........................................ Mouse .........................................
rem . . . . . . . . . . . . . . . . Additional mouse options . . . . . . . . . . . . . . . .

rem 1/6/10 - Enhance pointer precision (Mouse Acceleration)
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

rem ________________________________________________________________________________________
reg add "HKCU\Control Panel\Desktop" /v "SmoothScroll" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------- Bluetooth & Devices ----------------------------------
rem ....................................... Devices ........................................

rem 1 - Download over metered connections
reg add "HKLM\Microsoft\Windows\CurrentVersion\DeviceSetup" /v "CostedNetworkPolicy" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------- Bluetooth & Devices ----------------------------------
rem ..................................... Your Phone .......................................

rem 1 - Show me suggestions for using my Android phone with Windows
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility" /v "OptedIn" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Gaming ----------------------------------------
rem ....................................... Captures .......................................

rem 1 - Record what happened
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f

rem 1 - Capture audio when recording a game
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f

rem 1 - Capture mouse cursor when recording a game
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneCaptureEnabled" /t REG_DWORD /d "0" /f

rem 0 - Disable Fullscreen Optimizations for Current User / 0 - Enabled / 2 - Disabled
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "2" /f

rem 0 - Disable Game DVR / "Press Win + G to record a clip"
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f

reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxGipSvc start= disabled
sc config XboxNetApiSvc start= disabled
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Gaming ----------------------------------------
rem ...................................... Game Mode .......................................

rem 1 - Game Mode
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem Remove GameBarPresenceWriter.exe (to restore run SFC scan)
takeown /s %computername% /u %username% /f "%WINDIR%\System32\GameBarPresenceWriter.exe"
icacls "%WINDIR%\System32\GameBarPresenceWriter.exe" /inheritance:r /grant:r %username%:F
taskkill /im GameBarPresenceWriter.exe /f
del "%WINDIR%\System32\GameBarPresenceWriter.exe" /s /f /q


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Gaming ----------------------------------------
rem .................................... Xbox Game Bar .....................................

rem 1 - Open Xbox Game Bar
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Network & internet ----------------------------------
rem ............................... Advanced network settings ..............................

rem Show public/external IP
rem nslookup myip.opendns.com. resolver1.opendns.com

rem Windows wmic command line command
rem http://www.computerhope.com/wmic.htm
rem To get adapter's index number use
rem wmic nicconfig get caption,index,TcpipNetbiosOptions

rem Setup DNS Servers on DHCP Enabled Network (Cloudflare Malware)
rem wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("9.9.9.9","149.112.112.112")

rem Setup IP, Gateway and DNS Servers based on the MAC address (To Enable DHCP: wmic nicconfig where macaddress="28:E3:47:18:70:3D" call enabledhcp)
rem http://www.subnet-calculator.com/subnet.php?net_class=A
wmic nicconfig where macaddress="9C-6B-00-37-4B-DB" call EnableStatic ("192.168.9.2"), ("255.255.255.0")
wmic nicconfig where macaddress="9C-6B-00-37-4B-DB" call SetDNSServerSearchOrder ("45.90.28.99","45.90.30.99")
wmic nicconfig where macaddress="9C-6B-00-37-4B-DB" call SetGateways ("192.168.9.1")

rem 0 - Disable LMHOSTS Lookup on all adapters / 1 - Enable
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f

rem 2 - Disable NetBIOS over TCP/IP on all adapters / 1 - Enable / 0 - Default
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

rem NetBIOS / 0 - Disabled / 1 - Allowed / 2 - Disabled on public networks / 3 - Learning mode
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableNetbios" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem https://learn.microsoft.com/en-us/windows/win32/wininet/caching
rem https://www.codeproject.com/articles/1158641/windows-continuous-disk-write-plus-webcachev-dat-p
rem Disable WinInetCacheServer (WinINet Caching/V01.log/WebCacheV01.dat)
rem %LocalAppData%\Microsoft\Windows\WebCache
rem Take Ownership of the Registry key - https://www.youtube.com/watch?v=M1l5ifYKefg
rem CacheTask is required to be able to change PIN/password at lockscreen via Microsoft WWA Host (wwahost.exe) upon TPM reset after BIOS update
rem reg delete "HKCR\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
rem reg delete "HKCR\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
rem reg delete "HKCR\Wow6432Node\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
rem reg delete "HKCR\Wow6432Node\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
rem reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
rem reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
rem schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Disable

rem 0 - Disable WiFi Sense (shares your WiFi network login with other people)
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f

rem 1 - Turn on Mapper I/O (LLTDIO) driver
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /v "EnableLLTDIO" /t REG_DWORD /d "0" /f

rem 1 - Turn on Responder (RSPNDR) driver
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /v "EnableRspndr" /t REG_DWORD /d "0" /f

rem 1 - Turn off Microsoft Peer-to-Peer Networking Services
reg add "HKLM\Software\Policies\Microsoft\Windows\Peernet" /v "Disabled" /t REG_DWORD /d "1" /f

rem Disable Discovery of Designated Resolvers (DDR), a mechanism for DNS clients to use DNS records to discover a resolver's encrypted DNS configuration
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableDdr" /t REG_DWORD /d "0" /f

rem 3 - Require DoH / 2 - Allow DoH / 1 - Prohibit DoH
rem reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "DoHPolicy" /t REG_DWORD /d "3" /f

rem Disable IDN (internationalized domain name)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "DisableIdnEncoding" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableIdnMapping" /t REG_DWORD /d "0" /f

rem 1 - Discovery of Network-designated Resolvers DNS over TLS (DoT), DNS over HTTPS (DoH), DNS over QUIC (DoQ)
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableDnr" /t REG_DWORD /d "0" /f

rem Disable smart multi-homed name resolution
rem https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552(v=ws.10)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "DisableSmartNameResolution" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "DisableParallelAandAAAA" /t REG_DWORD /d "1" /f

rem Disable Multicast/mDNS repeater / https://f20.be/blog/mdns
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableMDNS" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f

rem Setup DNS over HTTPS (DoH)
rem netsh dns show encryption
rem netsh dns show global
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "0" /f

rem Setup DNS over HTTPS (DoH) Add Custom Servers
rem netsh dns add global doh=yes ddr=yes
rem HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers
rem netsh dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=149.112.112.112 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no

rem Setup DNS over TLS (DoT)
netsh dns set global doh=no
netsh dns add global dot=yes

rem netsh dns add encryption server=9.9.9.9 dothost=dns.quad9.net:853 autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=149.112.112.112 dothost=dns.quad9.net:853 autoupgrade=yes udpfallback=no

rem netsh dns add encryption server=45.90.28.99 dothost=:John--Router-8b7ea1.dns.nextdns.io autoupgrade=yes udpfallback=no
rem netsh dns add encryption server=45.90.30.99 dothost=:John--Router-8b7ea1.dns.nextdns.io autoupgrade=yes udpfallback=no

rem Restrict NTLM: Incoming NTLM traffic - Deny All
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d "2" /f
 
rem Restrict NTLM: Outgoing NTLM traffic to remote servers - Deny All
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d "2" /f

rem Disable IPv6
netsh int ipv6 isatap set state disabled
netsh int teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "6to4_State" /t REG_SZ /d "Disabled" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "ISATAP_State" /t REG_SZ /d "Disabled" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "Teredo_State" /t REG_SZ /d "Disabled" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "EnableICSIPv6" /t REG_DWORD /d "255" /f

rem 1 - Disable Domain Name Devolution (DNS AutoCorrect) / 0 - Enabled (Default)
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "UseDomainNameDevolution" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Background .......................................

rem Choose your picture (use PNG to display 100% quality of the original image)
reg add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "D:\OneDrive\Pictures\Wallpaper.png" /f

rem Choose a fit / 10 - Fill / 6 - Fit / 2 - Stretch / 0 - Tile/Center
reg add "HKCU\Control Panel\Desktop" /v "WallpaperStyle" /t REG_SZ /d "2" /f

rem ________________________________________________________________________________________
rem 60-100% Wallpaper's image quality / 85 - Default
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Colors .........................................

rem Accent color / 0 - Manual / 1 - Automatic (from wallpaper)
reg add "HKCU\Control Panel\Desktop" /v "AutoColorization" /t REG_SZ /d "1" /f

rem 1 - Transparency Effects
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f

rem 1 - Show accent color on Start and taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "1" /f

rem 1 - Show accent color on the title bars and windows borders
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Lock screen ......................................

rem Personalize your lock screen / 0 - Picture / 1 - Slideshow
reg add "HKCU\Control Panel\Desktop" /v "LockScreenAutoLockActive" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" /v "SlideshowEnabled" /t REG_DWORD /d "0" /f

rem 1 - Get fun facts, tips, and more from Windows and Cortana on your lock screen (Windows spotlight)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - Disable LockScreen
rem reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f
rem 1 - Disable Sign-in Screen Background Image
rem reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d "1" /f

rem 1 Disable Sign-in screen acrylic (blur) background 
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Lock screen ......................................
rem . . . . . . . . . . . . . . . . . Screen saver settings . . . . . . . . . . . . . . . .
 
rem 0 - No screen saver is selected / 1 - A screen saver is selected
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "1" /f

rem Specifies whether the screen saver is password-protected / 0 - No / 1 - Yes
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f

rem Specifies in seconds how long the System remains idle before the screen saver starts
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "250" /f

rem Screensaver - Mystify.scr
reg add "HKCU\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "Mystify.scr" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ........................................ Start .........................................

rem 1 - Show recommendations for tips, shortcuts, new apps, and more
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f

rem 1 - Show recently opened items in Start, Jump Lists, and File Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f
rem ________________________________________________________________________________________
rem Remove Start (to restore run SFC scan)
takeown /s %computername% /u %username% /f "%WINDIR%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe"
icacls "%WINDIR%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" /inheritance:r /grant:r %username%:F
taskkill /im StartMenuExperienceHost.exe /f
del "%WINDIR%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" /s /f /q


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Taskbar ........................................


rem Copilot / 0 - Off / 1 - On
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d "0" /f

rem Task view / 0 - Off / 1 - On
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f

rem Taskbar Alignment / 0 - Left / 1 - Center
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f

rem Widgets / 0 - Off / 1 - On (blocked in 24H2/1586)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f

rem 0 - Disable Widgets
reg add "HKCU\Software\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f

rem 1 - Disable Copilot
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\Shell\Copilot" /v "CopilotDisabledReason" /t REG_SZ /d "FeatureIsDisabled" /f
reg add "HKCU\Software\Microsoft\Windows\Shell\Copilot" /v "IsCopilotAvailable" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat" /v "IsUserEligible" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f

rem 1 - Show flashing on taskbar apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarFlashing" /t REG_DWORD /d "0" /f

rem Chat / 0 - Off / 1 - On
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f

rem 1 - Share any Window from Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSn" /t REG_DWORD /d "0" /f

rem Search / 0 - Hide Search on Taskbar / 1 - Show Search Icon Only on Taskbar / 2 - Show Search Box on Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f


rem ________________________________________________________________________________________
rem 1 - Always show all icons and notifications on the taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f

rem Disable Cortana
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableSearch" /t REG_DWORD /d "1" /f

rem Remove Search (Cortana/to restore run SFC scan)
rem winget uninstall "cortana"
takeown /s %computername% /u %username% /f "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"
icacls "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" /inheritance:r /grant:r %username%:F
taskkill /im SearchHost.exe /f
del "%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" /s /f /q


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Themes .........................................
rem . . . . . . . . . . . . . . . . . Desktop Icon Settings . . . . . . . . . . . . . . . .

rem Hide Control Panel
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d "1" /f

rem Hide Network
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d "1" /f

rem Hide OneDrive
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f

rem Hide Recycle Bin
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "1" /f

rem Hide Quick access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{679f85cb-0220-4080-b29b-5540cc05aab6}" /t REG_DWORD /d "1" /f

rem Hide This PC
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "1" /f

rem Hide User's Files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ...................................... Account info ....................................

rem Allow/Deny - Account info access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Allow" /f

rem Allow/Deny - Let apps access your account info / Microsoft Content / Email and accounts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.AccountsControl_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Allow" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f

rem ________________________________________________________________________________________
rem Allow/Deny - Allow access to account info on this device
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................... Activity history ...................................

rem 1 - Store my activity history on this device (not really working on 24H2)
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem .................................... App diagnostic ....................................

rem Allow/Deny - App diagnostic access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access diagnostic info about your other apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ....................................... Calendar .......................................

rem Allow/Deny - Calendar access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your calendar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ..................................... Call history .....................................

rem Allow/Deny - Call history access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your call history
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ Camera ........................................

rem Allow/Deny - Camera access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let Apps access your camera
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ....................................... Contacts .......................................

rem Allow/Deny - Contacts access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your contacts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................ Diagnostics & feedback ................................

rem 1 - Improve inking and typing
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\ImproveInkingAndTyping" /v "Value" /t REG_DWORD /d "0" /f

rem 3 - Send optional diagnostic data / 1 - No
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f

rem 1 - Tailored experiences
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem Send optional diagnostic data / 0 - Security (Not aplicable on Home/Pro, it resets to Basic) / 1 - Basic / 2 - Enhanced (Hidden) / 3 - Full
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f

rem Feedback Frequency - Windows should ask for my feedback: 0 - Never / Removed - Automatically
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ....................................... Documents ......................................

rem Allow/Deny - Documents library access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your documents library
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................... Downloads folder ...................................

rem Allow/Deny - Downloads folders access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your downloads folder
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ......................................... Email ........................................

rem Allow/Deny - Email access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your email
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ...................................... File System .....................................

rem Allow/Deny - File system access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f

rem Allow/Deny - Let apps access your file system
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f

rem Allow/Deny - 2fast - two factor authenticator supporting TOTP
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess\38343JanPhilippWeber.2fastTwoFactorAuthenticatorSu_nxr4mypqfqb9c" /v "Value" /t REG_SZ /d "Allow" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ General ......................................

rem 1 - Let apps show me personalized ads by using my advertising ID
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\AdvertisingInfo" /v "Value" /t REG_DWORD /d "0" /f

rem 0 - Let websites show me locally relevant content by accessing my language list (let browsers access your local language)
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f

rem 1 - Let Windows improve Start and search results by tracking app launches (Remember commands typed in Run) / 0 - Disable and Disable "Show most used apps"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f

rem 1 - Show me suggested content in the Settings app
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ....................................... Location .......................................

rem Allow/Deny - Location services
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your location
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ...................................... Messaging .......................................

rem Allow/Deny - Messaging access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps read or send messages
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ...................................... Microphone ......................................

rem Allow/Deny - Microphone access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your microphone
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem .................................... Music library .....................................

rem Allow/Deny - Allow access to music libraries on this device
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Allow apps to access your music library
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ..................................... Notifications ....................................

rem Allow/Deny - Notifications access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f

rem Allow/Deny - Let apps access your notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Allow" /f

rem 1 - Enable and Prioritize Edge Notifications by not showing them in the notification center 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\MSEdge" /v "ShowInActionCenter" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\MSEdge" /v "Rank" /t REG_DWORD /d "1" /f

rem 1 - Antivirus Disabled Notification
reg add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f

rem 0 - Security and Maitenance Notification
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f

rem 1 - Startup App Notification
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /v "Enabled" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ..................................... Other devices ....................................

rem Allow/Deny - Communicate with unpaired devices
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ..................................... Phone calls ......................................

rem Allow/Deny - Phone calls access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps make phone calls
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ....................................... Pictures .......................................

rem Allow/Deny - Pictures library access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your pictures library
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ Speech ........................................

rem 1 - Help make online speech recognition better
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ Radios ........................................

rem Allow/Deny - Radio control access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps control device radios
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem .................................. Screenshot borders ..................................

rem Allow/Deny - Screenshot borders access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps turn off the screenshot border
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let desktop apps turn off the screenshot border
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................. Screenshots and apps .................................

rem Allow/Deny - Screenshot access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps take screenshots of various windows or displays
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let desktop apps take screenshots of various windows or displays
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic\NonPackaged" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem .................................. Search permissions ..................................

rem 1 - Cloud content search
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f

rem 1 - Search history on this device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f

rem 1 - Cloud content search
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f

rem SafeSearch / 0 - Off / 1 - Moderate - 2 - Strict
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ......................................... Tasks ........................................

rem Allow/Deny - Task access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your tasks
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ Videos ........................................

rem Allow/Deny - Videos library access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your videos library
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................... Voice activation ...................................

rem 1 - Let apps access voice activation services
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "0" /f

rem 1 - Let apps use voice activation when device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ........................................ About .........................................

rem Rename this PC: FDDefine7Mini (Computer name should not be longer than 15 characters, no spaces either)
reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ActiveComputerName" /v "ComputerName" /t REG_SZ /d "FDDefine7Mini" /f
reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ComputerName" /v "ComputerName" /t REG_SZ /d "FDDefine7Mini" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "FDDefine7Mini" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "FDDefine7Mini" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ........................................ About .........................................
rem . . . . . . . . . . . . . . . . . . . System info . . . . . . . . . . . . . . . . . . .

rem ________________________________________________________________________________________
rem Support
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer" /t REG_SZ /d "TairikuOkami" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Model" /t REG_SZ /d "Asrock AMD Radeon RX 6600 Challenger D 8GB" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportHours" /t REG_SZ /d "Within 24-48 hours" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportPhone" /t REG_SZ /d "TairikuOkami@pm.me" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportURL" /t REG_SZ /d "https://www.elevenforum.com/members/tairikuokami.78" /f

rem Computer Description
reg add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "srvcomment" /t REG_SZ /d "500/100 MBps" /f

rem System info (Logo - 120x120.bmp)
rem winver
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Logo" /t REG_SZ /d "D:\OneDrive\Pictures\Logo.bmp" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "RegisteredOrganization" /t REG_SZ /d "(-_-)" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "RegisteredOwner" /t REG_SZ /d "Brony" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ........................................ About .........................................
rem . . . . . . . . . . . . . . . . . System protection . . . . . . . . . . . . . . . . . .

rem System Protection - Disable System restore and Set the minimal size
reg add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=320MB

rem ________________________________________________________________________________________
rem System Protection - Enable System restore and Set the size
rem vssadmin list shadowstorage
rem reg delete "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f
rem reg delete "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f
rem reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /v "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}" /t REG_MULTI_SZ /d "1" /f
rem schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Enable
rem vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=5GB
rem sc config wbengine start= demand
rem sc config swprv start= demand
rem sc config vds start= demand
rem sc config VSS start= demand


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ........................................ About .........................................
rem . . . . . . . . . . . . . . . . Advanced system settings . . . . . . . . . . . . . . . .

rem Performance - Advanced - Processor Scheduling
rem 0 - Foreground and background applications equally responsive / 1 - Foreground application more responsive than background / 2 - Best foreground application response time (Default)
rem 38 - Adjust for best performance of Programs / 24 - Adjust for best performance of Background Services
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "0" /f

rem Performance - Settings - Advanced - Virtual memory
rem Disable pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete

rem Performance - Visual effects / Keep: Show thumbnails instead of icons/Show windows contents/Smooth edges
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
rem reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f
rem reg add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
rem reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
rem reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
rem reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
rem reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f

rem Remote Settings - Disable Remote Assistance
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f

rem Startup and Recovery
rem 1 - Automatically Restart (on System Failure)
reg add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "0" /f

rem Startup and Recovery
rem 5 - 5 secs / Time to display list of operating systems
bcdedit /timeout 5

rem ________________________________________________________________________________________
rem Encrypt the Pagefile
rem fsutil behavior set EncryptPagingFile 1

rem Disable Display Mode Change Animation
reg add "HKLM\Software\Microsoft\Windows\Dwm" /v "ForceDisableModeChangeAnimation" /t REG_DWORD /d "1" /f

rem Disable Remote Assistance
sc config RemoteRegistry start= disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSAppCompat" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSUserEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ..................................... Clipboard ........................................

rem 1 - Clipboard history
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f

rem 1 - Sync across your devices
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard " /t REG_DWORD /d "0" /f

rem 0 - Suggested actions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ....................................... Display ........................................
rem . . . . . . . . . . . . . . . . . . . . Graphics . . . . . . . . . . . . . . . . . . . . 

rem Change default graphics settings
rem Variable refresh rate / Optimizations for windowed games
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings " /t REG_SZ /d "VRROptimizeEnable=0;SwapEffectUpgradeEnable=0;" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem .................................... Multitasking ......................................

rem 1 - When I drag a window, let me snap it without dragging all the way to the screen edge
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DITest" /t REG_DWORD /d "0" /f

rem 1 - Show snap layouts when I hover over a window's maximize button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssistFlyout" /t REG_DWORD /d "0" /f

rem 1 - Show snap layouts when I drag window to the top of my screen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapBar" /t REG_DWORD /d "0" /f

rem 1 - Show snap layouts that the app is part of when I hover over the taskbar buttons
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableTaskGroups" /t REG_DWORD /d "0" /f

rem Show tabs from apps when snapping or pressing ALt+Tab / 3 - Never / 2 - 3 tabs / 1 - 5 tabs / 0 - 20 tabs
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MultiTaskingAltTabFilter" /t REG_DWORD /d "3" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem .................................... Notifications .....................................

rem 1 - Show me the Windows welcome experience
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f

rem 1 - Get tips and suggestions when I use Windows
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f

rem 1 - Notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "1" /f

rem 1 - Offer suggestions on how I can set up my device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ....................................... Power ..........................................

rem Put my device to sleep after 30 minutes (ac-plugged in)
powercfg -change -standby-timeout-ac 30
powercfg -change -standby-timeout-dc 30

rem Turn off my screen after 25 minutes (ac-plugged in)
powercfg -change -monitor-timeout-ac 25
powercfg -change -monitor-timeout-dc 25


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ....................................... Storage ........................................


rem 1 - Storage Sense
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseTemporaryFilesCleanup" /t REG_DWORD /d "0" /f

rem fsutil storagereserve query C:
rem Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
rem 2/0/0 - Disable Reserved Storage (7GB) / 1/1/1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\MiscPolicyInfo" /v "ShippedWithReserves" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\PassedPolicy" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Time & language -------------------------------------
rem ..................................... Date & time .......................................

rem Time Zone - Central Europe Standard Time
tzutil /s "Central Europe Standard Time"

rem 1 - Show Shortened Time and Date on Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowShortenedDateTime" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowShortenedDateTimeRevision" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Time & language -------------------------------------
rem ..................................... Date & time .......................................
rem . . . . . . . . . . . . Additional date, time, & regional settings . . . . . . . . . . .

rem ________________________________________________________________________________________
rem To Change Clock to 12 hour or 24 hour Time Format on Default Lock Screen
rem https://www.tenforums.com/tutorials/73416-change-lock-screen-clock-12-hour-24-hour-format-windows-10-a.html#option2

rem 244 - Set Location to United States / 143 - Slovakia
reg add "HKCU\Control Panel\International\Geo" /v "Nation" /t REG_SZ /d "143" /f

rem Set Formats to Metric
reg add "HKCU\Control Panel\International" /v "iDigits" /t REG_SZ /d "2" /f
reg add "HKCU\Control Panel\International" /v "iLZero" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "iNegNumber" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iPaperSize" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iTLZero" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "sDecimal" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sNativeDigits" /t REG_SZ /d "0123456789" /f
reg add "HKCU\Control Panel\International" /v "sNegativeSign" /t REG_SZ /d "-" /f
reg add "HKCU\Control Panel\International" /v "sPositiveSign" /t REG_SZ /d "" /f
reg add "HKCU\Control Panel\International" /v "NumShape" /t REG_SZ /d "1" /f

rem Set Time to 24h / Monday
reg add "HKCU\Control Panel\International" /v "iCalendarType" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iDate" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iFirstDayOfWeek" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "iFirstWeekOfYear" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iTimePrefix" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "sDate" /t REG_SZ /d "-" /f
reg add "HKCU\Control Panel\International" /v "sList" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sLongDate" /t REG_SZ /d "d MMMM, yyyy" /f
reg add "HKCU\Control Panel\International" /v "sMonDecimalSep" /t REG_SZ /d "." /f
reg add "HKCU\Control Panel\International" /v "sMonGrouping" /t REG_SZ /d "3;0" /f
reg add "HKCU\Control Panel\International" /v "sMonThousandSep" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "dd-MMM-yy" /f
reg add "HKCU\Control Panel\International" /v "sTime" /t REG_SZ /d ":" /f
reg add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "HH:mm:ss" /f
reg add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f
reg add "HKCU\Control Panel\International" /v "sYearMonth" /t REG_SZ /d "MMMM yyyy" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Time & Language ------------------------------------
rem ....................................... Typing .........................................
rem . . . . . . . . . . . . . . . Advanced keyboard settings . . . . . . . . . . . . . . . .

rem Input language hot keys - Change Key Sequence
rem 3 - Not assigned / 2 - CTRL+SHIFT / 1 - Left ALT+SHIFT
reg add "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d "3" /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d "3" /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d "3" /f

rem ________________________________________________________________________________________
rem 2 - Enable Num Lock on Sign-in Screen / 2147483648 - Disable
reg add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
reg add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f


rem =================================== Windows Settings ===================================
rem ------------------------------------ Windows Update ------------------------------------
rem ................................... Advanced options ...................................


rem Adjust active hours / 0 - Manually / 1 - Automatically
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "SmartActiveHoursState" /t REG_DWORD /d "0" /f

rem Active hours (18 hours) 6am to 0am - Windows Updates will not automatically restart your device during active hours
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "6" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UserChoiceActiveHoursEnd" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UserChoiceActiveHoursStart" /t REG_DWORD /d "6" /f
rem ________________________________________________________________________________________
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "AutoRebootLimitInDays" /t REG_DWORD /d "365" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "SnoozeRebootHours" /t REG_DWORD /d "65535" /f

rem 1 - Disable File History (Creating previous versions of files/Windows Backup)
reg add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f

rem 1 - Disable Malicious Software Removal Tool offered via Windows Updates (MRT) + Disable Heartbeat Telemetry
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "SpyNetReportingLocation" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f

rem Choose how updates are delivered / 0 - Turns off Delivery Optimization / 1 - Gets or sends updates and apps to PCs on the same NAT only / 2 - Gets or sends updates and apps to PCs on the same local network domain / 3 - Gets or sends updates and apps to PCs on the Internet / 99 - Simple download mode with no peering / 100 - Use BITS instead of Windows Update Delivery Optimization
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f

rem Update apps automatically / 2 - Off / 4 - On
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "4" /f


rem ==================================== Windows Shell =====================================


rem Add Reset permissions to Shell/Manually Reset permissions/Take Ownership
rem http://lallouslab.net/2013/08/26/resetting-ntfs-files-permission-in-windows-graphical-utility

rem Take Ownership
rem Files/Folders - https://www.youtube.com/watch?v=x7gjZMvQHu4
rem Registry - https://www.youtube.com/watch?v=M1l5ifYKefg
rem https://ss64.com/nt/icacls.html
rem https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753024(v=ws.11)
rem https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753525(v=ws.11)

rem Add "Take Ownership" Option in Files and Folders Context Menu in Windows
rem reg add "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
rem reg add "HKCR\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
rem reg add "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
rem reg add "HKCR\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
rem reg add "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
rem reg add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
rem reg add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
rem reg add "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
rem reg add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
rem reg add "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f

rem Remove "Add to Favorites" Context Menu
reg delete "HKCR\*\shell\pintohomefile" /f

rem Remove "Copy as path" Context Menu
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu" /f

rem Remove "Open in Windows Terminal" Context Menu
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{9F156763-7844-4DC4-B2B1-901F640F5155}" /t REG_SZ /d "" /f

rem Remove "Send To" Context Menu
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" /f

rem Remove "Share" Context Menu
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing" /f

rem ________________________________________________________________________________________
rem Disable ADs and Auto-install subscribed/suggested apps (games like Candy Crush Soda Saga/Minecraft)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SlideshowEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000326Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f



rem =================================== Windows Support ====================================


rem Apps - FixWin - http://www.thewindowsclub.com/fixwin-for-windows-10
rem Windows Cleanup - https://drive.google.com/file/d/1AQLr94IQPBpZYEyKNi_CsI5WAOC4BCKp/view
rem Windows Drivers - https://www.catalog.update.microsoft.com
rem Windows Forums - https://www.elevenforum.com/whats-new
rem Windows Repair Install - https://www.elevenforum.com/t/repair-install-windows-11-with-an-in-place-upgrade.418
rem Windows Update Reset - https://github.com/ManuelGil/Reset-Windows-Update-Tool/releases
rem Windows Repair Toolbox - https://windows-repair-toolbox.com
rem Windows Update Troubleshooter - https://support.microsoft.com/en-us/windows/windows-update-troubleshooter-for-windows-10-19bc41ca-ad72-ae67-af3c-89ce169755dd
 
rem Boot into Recovery Mode 
rem Shutdown /f /r /o /t 0
 
rem Boot into safemode - https://www.elevenforum.com/t/boot-to-safe-mode-in-windows-11.538
rem bcdedit /set {identifier} safeboot minimal

rem Create shortcut to Settings (Volume Mixer)
rem %WinDir%\explorer.exe ms-settings:apps-volume

rem Create shortcut to Store Apps
rem shell:AppsFolder

rem DISM Commands - https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deployment-image-servicing-and-management--dism--command-line-options?view=windows-11
rem DISM /Cleanup-Wim
rem DISM /Get-WimInfo /WimFile:E:\sources\install.esd /index:1
rem DISM /Get-WimInfo /WimFile:E:\sources\install.wim
rem DISM /Get-WimInfo /WimFile:E:\sources\install.wim /index:1
rem DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:e:\sources\install.wim:1 /LimitAccess

rem DISM Error - DISM's source files could be found error codes: 0x800f081f or 0x800f0906 or 0x800f0907
rem https://www.wintips.org/fix-dism-source-files-could-not-be-found-windows-10-8
rem reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d "wim:D:\install.wim:1" /f
rem reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v "UseWindowsUpdate" /t REG_DWORD /d "2" /f
rem https://forums.mydigitallife.net/threads/is-there-any-way-to-refresh-windows-without-having-to-re-install-all-your-programs.82476/page-2#post-1622515

rem Fix boot - https://neosmart.net/wiki/bootrec/#Bootrec_in_Windows10
rem bootrec / fixmbr
rem bootrec / fixboot
rem bootrec / rebuildbcd
 
rem Edit Registry (if you can not boot into Windows)
rem Boot Windows USB - Repair - Troubleshoot - CMD - type/enter
rem c:
rem cd windows
rem cmd
rem regedit
rem Select HKLM (or required key)
rem File - Load Hive - %WinDir%\System32\Config (select required Hive, like System/HKLM)
rem SAVE - Unload Hive (when you finish editing)

rem List processes/services
rem tasklist>c:\list.txt
rem tasklist/svc>c:\processlist.txt
rem wmic startup get caption,command > c:\StartupApps.txt

rem Malware Live - Real AV Testing
rem rem https://app.any.run/submissions
rem https://urlhaus.abuse.ch/browse
rem https://www.hybrid-analysis.com/submissions/sandbox/files
rem https://www.phishtank.com

rem Malware Tests - AV Check
rem rem https://demo.wd.microsoft.com/?ocid=cx-wddocs-testground
rem https://www.amtso.org/feature-settings-check-potentially-unwanted-applications
rem https://www.wicar.org/test-malware.html

rem Malware URL Check
rem https://urlscan.io
rem https://www.malware-traffic-analysis.net
rem https://www.virustotal.com/gui/home/url
rem https://www.urlvoid.com

rem Reliability Monitor
rem perfmon /rel

rem https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb490876(v=technet.10)?
rem https://docs.microsoft.com/en-us/archive/blogs/b8/redesigning-chkdsk-and-the-new-ntfs-health-model
rem Repair bad sectors
rem chkdsk %SystemDrive% /r

rem Reset digital certificates used by Windows and browsers
rem https://howtoedge.com/purge-the-catroot2-folder

rem Reset password/gain admin access/enable local admin account
rem https://www.technibble.com/bypass-windows-logons-utilman/
rem copy /y c:\windows\system32\cmd.exe c:\windows\system32\utilman.exe
rem net user username password
rem net user Administrator /active:yes
rem net user Administrator *
rem net user NewGuy * /add
rem net localgroup Administrators NewGuy /add

rem Access CMD with SYSTEM rights at logon (Win+U)
takeown /s %computername% /u %username% /f "%WINDIR%\System32\utilman.exe"
icacls "%WINDIR%\System32\utilman.exe" /grant:r %username%:F
copy /y %WINDIR%\System32\cmd.exe %WINDIR%\System32\utilman.exe
takeown /s %computername% /u %username% /f "%WINDIR%\System32\sethc.exe"
icacls "%WINDIR%\System32\sethc.exe" /grant:r %username%:F
copy /y %WINDIR%\System32\cmd.exe %WINDIR%\System32\sethc.exe

rem To restart explorer
rem taskkill /im explorer.exe /f & explorer.exe

rem User Accounts - netplwiz

rem Windows Updates Block
rem 1. https://www.sordum.org/9470/windows-update-blocker-v1-8
rem 2. Block svchost.exe in the firewall, ports 80/443 to avoid blocking DHCP/DNS, still it will block updating certificates needed by browsers! So use temporarily.
rem 3. Create a nonexistent symlink, but it will probably block MS store updates as well!
rem rd "%WINDIR%\SoftwareDistribution\Download" /s /q
rem mklink /d "%WINDIR%\SoftwareDistribution\Download" "X:\Download"


rem ==================================== Windows Waypoint ==================================


timeout 5

taskkill /im brave.exe /f
taskkill /im dllhost.exe /f
taskkill /im firefox.exe /f
taskkill /im librewolf.exe /f
taskkill /im msedge.exe /f
taskkill /im rundll32.exe /f
taskkill /im steam.exe /f
taskkill /im tor.exe /f

rem https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade
winget upgrade --all -h --include-unknown --accept-package-agreements --accept-source-agreements
timeout 5

rem https://kalilinuxtutorials.com/webview2-cookie-stealer
fsutil usn deletejournal /d /n c:

taskkill /im cncmd.exe /f
taskkill /im QtWebEngineProcess.exe /f
taskkill /im RadeonSoftware.exe /f
taskkill /im amdow.exe /f
taskkill /im AMDRSServ.exe /f

rem Run Wise Disk Cleaner
start "" /wait "%ProgramFiles(x86)%\Wise\Wise Disk Cleaner\WiseDiskCleaner.exe" -a -all

rem Run Wise Registry Cleaner
start "" /wait "%ProgramFiles(x86)%\Wise\Wise Registry Cleaner\WiseRegCleaner.exe" -a -all

rem Trim some Edges - edge://settings/content/cookies/siteData
del "%LocalAppData%\Microsoft\Edge\User Data\Default\*history*." /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\arbitration_service_config.json" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Custom Dictionary.txt" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\DashTrackerDatabase" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\DashTrackerDatabase-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\default_cloud_config.json" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\DIPS" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\DIPS-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\HubApps" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\HubApps Icons" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\HubApps Icons-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\InterestGroups" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\LOG" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\LOG.old" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\MediaDeviceSalts" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\MediaDeviceSalts-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Network Action Predictor" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Network Action Predictor-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Network Persistent State" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\PreferredApps" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\PrivateAggregation" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Reporting and NEL" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Reporting and NEL-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\QuotaManager" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\QuotaManager-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\SharedStorage" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Shortcuts" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Shortcuts-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Top Sites" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Top Sites-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\uu_host_config" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Visited Links" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Vpn Tokens" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\WebAssistDatabase" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\WebAssistDatabase-journal" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Web Data" /s /f /q
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Web Data-journal" /s /f /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Asset Store" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\AssistanceHome" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\blob_storage" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\BudgetDatabase" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Code Cache" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Collections" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\commerce_subscription_db" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Continuous Migration" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\databases" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\DawnGraphiteCache" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\DawnWebGPUCache" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\discounts_db" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\DNR Extension Rules" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Download Service" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\DualEngine" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgeCoupons" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgeEDrop" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgeHubAppUsage" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgePushStorageWithConnectTokenAndKey" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgePushStorageWithWinRt" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgeTravel" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EdgeWallet" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\EntityExtraction" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Feature Engagement Tracker" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\GPUCache" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\File System" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\IndexedDB" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\JumpListIconsRecentClosed" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\JumpListIconsRecentWorkspacesV2" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\JumpListIconsTopSites" /s /q
rem rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Local Storage" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\MediaFoundationCdmStore" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Nurturing" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\optimization_guide_hint_cache_store" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\optimization_guide_model_metadata_store" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\parcel_tracking_db" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\PersistentOriginTrials" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\PriceComparison" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Password_Diagnostics" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Pdf" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\PDF Restore Data" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Platform Notifications" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Safe Browsing Network" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Segmentation Platform" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\SemanticEncoder.db" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Service Worker" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Session Storage" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Sessions" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Shared Dictionary" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\shared_proto_db" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Site Characteristics Database" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Storage" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\VideoDecodeStats" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\WebrtcVideoStats" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Web Applications" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\WebStorage" /s /q
rd "%LocalAppData%\Microsoft\Edge\User Data\Default\Workspaces" /s /q

start "" "D:\OneDrive\Downloads\CD.bat"
start "" "D:\OneDrive\Downloads\Microsoft Defender Disable.bat"

timeout 5

shutdown /s /f /t 0

rem My security: NextDNS Free with Cache Boost ON acting as AV, using separate profiles for browsers (Edge for internet, Brave for Youtube, LibreWolf for FB) and Windows
rem Browsers can connect only to their domains, the rest of the net is blocked as well as 95% TLDs https://ibb.co/Ld4S1Dp / https://ibb.co/QHTH33P / https://ibb.co/cvdKxTX

rem https://ibb.co/bP9w8tw - Windows 11 Home 24H2 (26100.2454) Quiet Edition - 68 processes / 675 threads / 28205 handles / 3,6GB RAM (1.1GB used by ramdisk)
