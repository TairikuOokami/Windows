rem Unlink OneDrive!

pause

rem Disable Stupid Smart App Control blocking legitimate apps like VisualC++ and DX9
reg add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f

start windowsdefender:
rem Update Windows, Defender, Restart
rem Disable Tamper and Real Protection in Defender
rem Run "MD Disable.bat" TWICE - RESTART!

pause

rem Change D/E after removing pagefile
rem Remove the user from D:\
rem Take Ownership of D/E
explorer

pause

rem Select to Save files locally then Link OneDrive to change the location!
rem Unlock Personal Vault afterwards to install OneDrive in a proper location!

pause

rem Disable Hibernation and thus also Fast Startup
powercfg -h off

rem Disable Windows Recovery Partition
rem reagentc /info
rem reagentc /disable
rem reagentc /enable

rem Disable Reserved Storage (7GB)
rem fsutil storagereserve query C:
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ActiveComputerName" /v "ComputerName" /t REG_SZ /d "FDDefine7Mini" /f
reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ComputerName" /v "ComputerName" /t REG_SZ /d "FDDefine7Mini" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "FDDefine7Mini" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "FDDefine7Mini" /f

rem DISM /Online /Get-Capabilities
rem https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11
DISM /Online /Add-Capability /CapabilityName:WMIC~~~~
Dism /Online /NoRestart /Remove-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0

start "" "D:\OneDrive\Setup"
rem Install Chipset Drivers and RESTART!
rem Install GPU Drivers and RESTART!

pause

rem Disable Indexing C:
explorer

pause

takeown /s %computername% /u %username% /f D: /r /d y
icacls D: /inheritance:r
icacls D: /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D: /grant "System":(OI)(CI)RX /t /l /q /c
icacls D: /grant "Users":(OI)(CI)RX /t /l /q /c

takeown /s %computername% /u %username% /f E: /r /d y
icacls E: /inheritance:r
icacls E: /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls E: /grant "System":(OI)(CI)F /t /l /q /c
icacls E: /grant "Users":(OI)(CI)RX /t /l /q /c

pause

takeown /s %computername% /u %username% /f D:\OneDrive /r /d y
icacls D:\OneDrive /inheritance:r
icacls D:\OneDrive /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D:\OneDrive /grant "System":(OI)(CI)RX /t /l /q /c
icacls D:\OneDrive /grant "Users":(OI)(CI)RX /t /l /q /c

takeown /s %computername% /u %username% /f D:\RamDisk /r /d y
icacls D:\RamDisk /inheritance:r
icacls D:\RamDisk /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D:\RamDisk /grant:r "System":(OI)(CI)F /t /l /q /c
icacls D:\RamDisk /grant "Users":(OI)(CI)RX /t /l /q /c

takeown /s %computername% /u %username% /f D:\Steam /r /d y
icacls D:\Steam /inheritance:r
icacls D:\Steam /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D:\Steam /grant:r "System":(OI)(CI)F /t /l /q /c
icacls D:\Steam /grant "Users":(OI)(CI)RX /t /l /q /c

pause

rem Access CMD with SYSTEM rights at logon (Win+U)
takeown /s %computername% /u %username% /f "%WINDIR%\System32\utilman.exe"
icacls "%WINDIR%\System32\utilman.exe" /grant:r %username%:F
copy /y %WINDIR%\System32\cmd.exe %WINDIR%\System32\utilman.exe
takeown /s %computername% /u %username% /f "%WINDIR%\System32\sethc.exe"
icacls "%WINDIR%\System32\sethc.exe" /grant:r %username%:F
copy /y %WINDIR%\System32\cmd.exe %WINDIR%\System32\sethc.exe

rem Disable Auto-install subscribed/suggested apps (games like Candy Crush Soda Saga/Minecraft)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

rem Disable Bitlocker, EFS and Decrypt C:
rem manage-bde -status
reg add "HKLM\System\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d "1" /f
fsutil behavior set disableencryption 1
manage-bde -off C:
manage-bde -off D:
manage-bde -off E:
cipher /d /s:C:\

rem Windows File Compression
rem compact /compactos:query
fsutil behavior set disablecompression 1
compact /compactos:never
rem compact /CompactOs:always
rem compact /c /i /q /f /s:C:\
rem compact /u /i /q /f /s:C:\
rem compact /u /i /q /f /s:Z:\
rem compact /u /i /q /f /s:D:\Documents\
rem compact /u /i /q /f /s:D:\OneDrive\Pictures\

rem Disable pagefile
rem fsutil behavior set EncryptPagingFile 1
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete

rem Setup Network (NetBIOS might be required for aDSL/LAN)
rem Disable IPv6/LMHOSTS lookup/NetBIOS and Set DNS Servers
wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("94.140.14.14","94.140.15.15")
netsh int ipv6 isatap set state disabled
netsh int teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "6to4_State" /t REG_SZ /d "Disabled" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "ISATAP_State" /t REG_SZ /d "Disabled" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "Teredo_State" /t REG_SZ /d "Disabled" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "EnableICSIPv6" /t REG_DWORD /d "255" /f
wmic nicconfig where macaddress="9C-6B-00-37-4B-DB" call EnableStatic ("192.168.9.2"), ("255.255.255.0")
wmic nicconfig where macaddress="9C-6B-00-37-4B-DB" call SetDNSServerSearchOrder ("45.90.28.99","45.90.30.99")
wmic nicconfig where macaddress="9C-6B-00-37-4B-DB" call SetGateways ("192.168.9.1")
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

rem Enable DoT
netsh dns set global doh=no
netsh dns add global dot=yes ddr=no
netsh dns set global dot=yes ddr=no
netsh dns add encryption server=94.140.14.14 dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dohtemplate=https://dns.adguard-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.14.14 dothost=dns.adguard-dns.com:853 autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dothost=dns.adguard-dns.com:853 autoupgrade=yes udpfallback=no

rem Enable NextDNS DoT - 45.90.28.99/45.90.30.99
start "" /wait "D:\OneDrive\Downloads\UnValidate.bat"
start ms-settings:network-ethernet

pause

rem Activate Windows
slmgr.vbs /ato

rem Remove Windows product key from the registry
slmgr /cpky

rem pause

rem https://raw.githubusercontent.com/microsoft/windows-dev-box-setup-scripts/refs/heads/master/scripts/RemoveDefaultApps.ps1
rem C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle  | Where-Object {$_.NonRemovable -eq $False} | Select-Object Name, PackageFullName"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Clipchamp.Clipchamp" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.BingNews" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.BingSearch" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.BingWeather" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.Copilot" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.GamingApp" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.GetHelp" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.HEVCVideoExtension" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.PowerAutomateDesktop" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.ScreenSketch" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.StartExperiencesApp" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.Todos" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WidgetsPlatformRuntime" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.Windows.DevHome" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.Windows.Photos" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WindowsAlarms" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WindowsCamera" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WindowsNotepad" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.WindowsTerminal" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.YourPhone" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.ZuneMusic" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.Xbox.TCUI" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.XboxGamingOverlay" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "MicrosoftCorporationII.MicrosoftFamily" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "MicrosoftCorporationII.QuickAssist" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "MicrosoftWindows.Client.WebExperience" | Remove-AppxPackage -AllUsers"

pause

winget uninstall "Microsoft Edge Game Assist"
winget uninstall "Microsoft.Teams"
winget uninstall "Outlook for Windows"

rem Uninstall Remote Desktop Connection and check for new bloatware
start ms-settings:installed-apps

pause

rem https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-or-disable-windows-features-using-dism?view=windows-11
rem DISM /Online /Get-Features /Format:Table
rem DISM /Online /Get-FeatureInfo /FeatureName:Recall
rem DISM /Online /Get-Packages /Format:Table
rem DISM /Online /Get-ProvisionedAppxPackages | select-string Packagename
Dism /Online /Disable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MSRDC-Infrastructure /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:NetFx4-AdvSrvs /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-Foundation-Features /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-XPSServices-Features /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Recall /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:SMB1Protocol /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:SearchEngine-Client-Package /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Windows-Defender-Default-Definitions /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

pause

start "" /wait "D:\OneDrive\Setup\install.bat"

pause

start "" /wait "%ProgramFiles%\AIM Toolkit\RamDiskUI.exe"
start "" /wait "%ProgramFiles%\AIM Toolkit\config.exe"

pause

rem Single-click to open an item (point to select)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "2400000017a8000000000000000000000000000001000000130000000000000073000000" /f

rem 1 - Launch folder windows in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f

rem 0 - All of the components of Windows Explorer run a single process / 1 - All instances of Windows Explorer run in one process and the Desktop and Taskbar run in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f

rem Windows Settings - System - System info - Advanced system settings - Keep: Show thumbnails instead of icons/Show windows contents/Smooth edges
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f

rem Ponified system icons / 3 - Default / 4 - Opened
rem https://www.tenforums.com/tutorials/81222-change-icons-folders-pc-windows-10-a.html
reg add "HKCR\CompressedFolder\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\batfile\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Join.me.ico" /f
reg add "HKCR\Folder\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\spitfireicon.ico" /f
reg add "HKCR\regfile\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Cheerilee.ico" /f
reg add "HKCR\txtfile\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Notepad.ico" /f
reg add "HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\SyncToy.ico" /f
reg add "HKCU\Software\Classes\CLSID\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\applebloomicon.ico" /f
reg add "HKCU\Software\Classes\CLSID\{088e3905-0323-4b02-9826-5d99428e115f}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\scooticon2.ico" /f
reg add "HKCU\Software\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Sweetiebelleicon.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\C\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\rarityticon2.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\D\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Pinkie_Pie.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\E\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\fluttericon.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\Z\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Speed Runners.ico" /f
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "3" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Folder - UserFluttershy.ico" /f
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "4" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\fluttericon.ico" /f
rem reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\explorer\Shell Icons" /v "3" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Folder - UserFluttershy.ico" /f
rem reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\explorer\Shell Icons" /v "4" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\fluttericon.ico" /f

rem Move Desktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "%USERPROFILE%\Desktop" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" /t REG_EXPAND_SZ /d "%USERPROFILE%\Desktop" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "%USERPROFILE%\Desktop" /f
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%USERPROFILE%\Desktop" /s /q
md "%USERPROFILE%\Desktop"
rem rem mklink /d "%USERPROFILE%\Desktop" "Z:\Desktop"

rem Move Documents
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Personal" /t REG_SZ /d "D:\OneDrive\Documents" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /t REG_EXPAND_SZ /d "D:\OneDrive\Documents" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Personal" /t REG_EXPAND_SZ /d "D:\OneDrive\Documents" /f
takeown /s %computername% /u %username% /f "%USERPROFILE%\Documents" /r /d y
icacls "%USERPROFILE%\Documents" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%USERPROFILE%\Documents" /s /q
mklink /d "%USERPROFILE%\Documents" "D:\OneDrive\Documents"

rem Move Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_SZ /d "D:\OneDrive\Downloads" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_EXPAND_SZ /d "D:\OneDrive\Downloads" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" /t REG_EXPAND_SZ /d "D:\OneDrive\Downloads" /f
rd "%USERPROFILE%\Downloads" /s /q
mklink /d "%USERPROFILE%\Downloads" "D:\OneDrive\Downloads"

rem Move Pictures
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /t REG_SZ /d "D:\OneDrive\Pictures" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_EXPAND_SZ /d "D:\OneDrive\Pictures" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /t REG_EXPAND_SZ /d "D:\OneDrive\Pictures" /f

rem Move Videos
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /t REG_SZ /d "D:\Movies" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /t REG_EXPAND_SZ /d "D:\Movies" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /t REG_EXPAND_SZ /d "D:\Movies" /f

pause

winget install Microsoft.AppInstaller --accept-package-agreements --accept-source-agreements
winget install Microsoft.DirectX --accept-package-agreements --accept-source-agreements

winget import -i D:\OneDrive\Setup\winget.txt --accept-package-agreements --accept-source-agreements

winget install Brave.Brave --accept-package-agreements --accept-source-agreements
winget install CreativeTechnology.SoundBlasterCommand --accept-package-agreements --accept-source-agreements
winget install Kingston.SSDManager --accept-package-agreements --accept-source-agreements
winget install LibreWolf.LibreWolf --accept-package-agreements --accept-source-agreements
winget install Logitech.UnifyingSoftware --accept-package-agreements --accept-source-agreements
winget install Rizonesoft.Notepad3 --accept-package-agreements --accept-source-agreements
winget install M2Team.NanaZip --accept-package-agreements --accept-source-agreements
winget install Microsoft.OneDrive --accept-package-agreements --accept-source-agreements
winget install MPC-BE.MPC-BE --accept-package-agreements --accept-source-agreements
winget install SumatraPDF.SumatraPDF --accept-package-agreements --accept-source-agreements
winget install TheDocumentFoundation.LibreOffice --accept-package-agreements --accept-source-agreements
winget install WinsiderSS.SystemInformer.Canary --accept-package-agreements --accept-source-agreements
winget install XnSoft.XnView.Classic --accept-package-agreements --accept-source-agreements
winget install XSplit.Broadcaster --accept-package-agreements --accept-source-agreements

pause

rem 2fast – Two Factor Authenticator\
winget install 9P9D81GLH89Q --accept-package-agreements --accept-source-agreements

rem Audials Radio
winget install XPDM0S9P0J5LT4 --accept-package-agreements --accept-source-agreements

rem Wise Disk Cleaner
winget install XP9CW3GPQQS852 --accept-package-agreements --accept-source-agreements

rem Wise Registry Cleaner
winget install XPDLS1XBTXVPP4 --accept-package-agreements --accept-source-agreements

pause

‪start "" /wait "D:\OneDrive\Setup\GIHO_TubeGet_Pro.exe"
start "" /wait "D:\OneDrive\Setup\instalatoraplikacii.exe"
start "" /wait "D:\OneDrive\Setup\tracksim-installer.exe"
start "" /wait "D:\OneDrive\Setup\AESeriesDriverInstaller_W10.exe"

pause

rem Install paid Bitwarden, eM Client, HEVC, Netflix, Ruf
us

start ms-windows-store:

pause

rem Enable PreOS and Create a Backup

start "" /wait "C:\Program Files\Hasleo\Hasleo Backup Suite\bin\BackupMainUI.exe"

pause

rem Restart in ...

pause

shutdown /r /f /t 0
