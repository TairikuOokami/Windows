rem DO NOT enable OneDrive during Windows setup, otherwise you will not be able to choose the folder's location!

powercfg -h off

rem Disable Reserved Storage (7GB)
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ActiveComputerName" /v "ComputerName" /t REG_SZ /d "LianLiPC-7NB" /f
reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ComputerName" /v "ComputerName" /t REG_SZ /d "LianLiPC-7NB" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "LianLiPC-7NB" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "LianLiPC-7NB" /f

start ms-settings:windowsupdate-action
rem Check for updates and Optional updates in Advanced options and RESTART!
rem In the meantime install store apps, app installer included (winget)!

pause

start "" "D:\Software"
rem Install Chipset Drivers and GPU Drivers and RESTART!

pause

start windowsdefender:
rem Disable Tamper and Real Protection in Defender

pause

takeown /s %computername% /u %username% /f D: /r /d y
icacls D: /inheritance:r
icacls D: /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D: /grant "Users":(OI)(CI)RX /t /l /q /c

takeown /s %computername% /u %username% /f D:\OneDrive /r /d y
icacls D:\OneDrive /inheritance:r
icacls D:\OneDrive /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D:\OneDrive /grant "Users":(OI)(CI)RX /t /l /q /c
icacls D:\OneDrive /deny "System":(OI)(CI)F /t /l /q /c

takeown /s %computername% /u %username% /f D:\Documents /r /d y
icacls D:\Documents /inheritance:r
icacls D:\Documents /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D:\Documents /grant "Users":(OI)(CI)RX /t /l /q /c
icacls D:\Documents /deny "System":(OI)(CI)F /t /l /q /c

takeown /s %computername% /u %username% /f D:\Software /r /d y
icacls D:\Software /inheritance:r
icacls D:\Software /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls D:\Software /grant "Users":(OI)(CI)RX /t /l /q /c
icacls D:\Software /deny "System":(OI)(CI)F /t /l /q /c

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
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

rem Disable EFS and Decrypt everything on C:
fsutil behavior set disableencryption 1
cipher /d /s:C:\

rem Enable Windows File Compression
rem compact /compactos:query
fsutil behavior set disablecompression 0
compact /CompactOs:always

rem Disable pagefile
rem fsutil behavior set EncryptPagingFile 1
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete

rem Setup Network (NetBIOS might be required for aDSL/LAN)
rem Disable IPv6/LMHOSTS lookup/NetBIOS and Set DNS Servers
wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("9.9.9.9","149.112.112.112")
netsh int ipv6 isatap set state disabled
netsh int teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f
wmic nicconfig where macaddress="00:D8:61:6E:E8:C5" call EnableStatic ("192.168.9.2"), ("255.255.255.0")
wmic nicconfig where macaddress="00:D8:61:6E:E8:C5" call SetDNSServerSearchOrder ("45.90.28.91","45.90.30.91")
wmic nicconfig where macaddress="00:D8:61:6E:E8:C5" call SetGateways ("192.168.9.1")
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

rem Setup Encrypted DNS
start "" /wait "D:\OneDrive\Downloads\UnValidate.bat"
start ms-settings:network-ethernet

pause

rem winget list
winget uninstall "cortana"
winget uninstall "get help"
winget uninstall "microsoft people"
winget uninstall "microsoft photos"
winget uninstall "microsoft tips"
winget uninstall "windows alarms & clock"
winget uninstall "windows camera"
winget uninstall "windows maps"
winget uninstall "windows web experience pack"
winget uninstall "xbox game bar"
winget uninstall "xbox game bar plugin"
winget uninstall "xbox game speech window"
winget uninstall "xbox identity provider"
winget uninstall "your phone"

pause

rem https://msdn.microsoft.com/en-us/windows/hardware/commercialize/manufacture/desktop/enable-or-disable-windows-features-using-dism
rem Dism /Online /Get-Features
Dism /Online /Disable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MSRDC-Infrastructure /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-Foundation-Features /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Printing-XPSServices-Features /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:SMB1Protocol /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:SearchEngine-Client-Package /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:Windows-Defender-Default-Definitions /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
Dism /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart
rem Dism /Online /Enable-Feature /FeatureName:NetFx3 /All /Source:E:\sources\sxs /LimitAccess

rem start "" /wait "D:\OneDrive\Setup\dotNetFx35_WX_9_x86_x64.exe" /ai

rem Activate Windows
slmgr.vbs /ato

rem Remove Windows product key from the registry
slmgr /cpky

pause

start "" /wait "D:\OneDrive\Setup\install.bat"

pause

start "" /wait "%ProgramFiles%\ImDisk\RamDiskUI.exe"

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
reg add "HKCR\7-Zip.001\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\7-Zip.7z\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\7-Zip.cab\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\7-Zip.rar\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\7-Zip.wim\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\7-Zip.zip\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\WinZIP Folder.ico" /f
reg add "HKCR\batfile\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Join.me.ico" /f
reg add "HKCR\Folder\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\fluttericon.ico" /f
reg add "HKCR\regfile\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Cheerilee.ico" /f
reg add "HKCR\txtfile\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Notepad.ico" /f
reg add "HKCU\Software\Classes\CLSID\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\applebloomicon.ico" /f
reg add "HKCU\Software\Classes\CLSID\{088e3905-0323-4b02-9826-5d99428e115f}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\scooticon2.ico" /f
reg add "HKCU\Software\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Sweetiebelleicon.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\C\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\rarityticon2.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\D\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Pinkie_Pie.ico" /f
reg add "HKCU\Software\Classes\Applications\Explorer.exe\Drives\Z\DefaultIcon" /ve /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Speed Runners.ico" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "3" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Folder - UserFluttershy.ico" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "4" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\fluttericon.ico" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\explorer\Shell Icons" /v "3" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\Folder - UserFluttershy.ico" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\explorer\Shell Icons" /v "4" /t REG_SZ /d "D:\OneDrive\Pictures\MLP Icons\Folders\fluttericon.ico" /f

rem Move Desktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "Z:\Desktop" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}" /t REG_EXPAND_SZ /d "Z:\Desktop" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "Z:\Desktop" /f
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%USERPROFILE%\Desktop" /s /q
md "Z:\Desktop"
mklink /d "%USERPROFILE%\Desktop" "Z:\Desktop"

rem Move Documents
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Personal" /t REG_SZ /d "D:\Documents" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /t REG_EXPAND_SZ /d "D:\Documents" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Personal" /t REG_EXPAND_SZ /d "D:\Documents" /f
takeown /s %computername% /u %username% /f "%USERPROFILE%\Documents" /r /d y
icacls "%USERPROFILE%\Documents" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%USERPROFILE%\Documents" /s /q
mklink /d "%USERPROFILE%\Documents" "D:\Documents"

rem Move Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_SZ /d "D:\OneDrive\Downloads" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_EXPAND_SZ /d "D:\OneDrive\Downloads" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}" /t REG_EXPAND_SZ /d "D:\OneDrive\Downloads" /f

rem Move Pictures
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /t REG_SZ /d "D:\OneDrive\Pictures" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_EXPAND_SZ /d "D:\OneDrive\Pictures" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /t REG_EXPAND_SZ /d "D:\OneDrive\Pictures" /f

rem Move Videos
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /t REG_SZ /d "D:\Movies" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /t REG_EXPAND_SZ /d "D:\Movies" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /t REG_EXPAND_SZ /d "D:\Movies" /f

rem Temp Folders to RAMDisk
reg add "HKCU\Environment" /v "TEMP" /t REG_EXPAND_SZ /d "Z:\TEMP" /f
reg add "HKCU\Environment" /v "TMP" /t REG_SZ /d "Z:\TEMP" /f

start "" /wait "D:\Software\directx_Jun2010_redist\DXSETUP.exe"
start "" /wait "D:\OneDrive\Setup\ADATA_SSDToolBoxSetup.exe"
start "" /wait "D:\OneDrive\Setup\SBZMasterInstaller_3.4.98.00.exe"
start "" /wait "D:\OneDrive\Setup\instalatoraplikacii.exe"
start "" /wait "D:\OneDrive\Setup\wfc6setup.exe"

pause

start "" /wait "D:\Software"

rem Restart in ...

pause

shutdown /r /f /t 0
