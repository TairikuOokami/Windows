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

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle  | Where-Object {$_.NonRemovable -eq $False} | Select-Object Name, PackageFullName"

pause

winget uninstall "Microsoft Edge Game Assist"

start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.Copilot" | Remove-AppxPackage -AllUsers"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage -AllUsers"

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

start "" /wait "C:\Program Files (x86)\Creative\Sound Blaster Command\Creative.SBCommand.exe"

control

pause

rem AMD Controller Emulation
pnputil /disable-device "ROOT\AMDXE\0000"

rem AMD Crash Defender
pnputil /disable-device "ROOT\AMDLOG\0000"

rem AMD High Definition Audio Device
pnputil /disable-device "HDAUDIO\FUNC_01&VEN_1002&DEV_AA01&SUBSYS_00AA0100&REV_1008\5&1CD0132C&0&0001"

rem AMD High Definition Audio Device
pnputil /disable-device "HDAUDIO\FUNC_01&VEN_1002&DEV_AA01&SUBSYS_00AA0100&REV_1008\7&ADEDD0B&0&0001"

rem AMD PSP 11.0 Device
pnputil /disable-device "PCI\VEN_1022&DEV_15C7&SUBSYS_15C71022&REV_00\4&98C338A&0&0241"

rem AMD Radeon 760M Graphics
pnputil /disable-device "PCI\VEN_1002&DEV_15BF&SUBSYS_35BF1849&REV_05\4&98C338A&0&0041"

rem AMD SMBUS
pnputil /disable-device "PCI\VEN_1022&DEV_790B&SUBSYS_790B1849&REV_71\3&11583659&0&A0"

rem AMD Streaming Audio Device
pnputil /disable-device "ROOT\AMDSAFD&FUN_01&REV_01\0000"

rem Composite Bus Enumerator
pnputil /disable-device "ROOT\COMPOSITEBUS\0000"

rem Microsoft GS Wavetable Synth
pnputil /disable-device "SWD\MMDEVAPI\MICROSOFTGSWAVETABLESYNTH"

rem Microsoft Hyper-V Virtualization Infrastructure Driver
pnputil /disable-device "ROOT\VID\0000"

rem Microsoft Kernel Debug Network Adapter
pnputil /disable-device "ROOT\KDNIC\0000"

rem NDIS Virtual Network Adapter Enumerator
pnputil /disable-device "ROOT\NDISVIRTUALBUS\0000"

rem NPU Compute Accelerator Device
pnputil /disable-device "PCI\VEN_1022&DEV_1502&SUBSYS_15021022&REV_00\4&92D7D1B&0&0142"

rem Remote Desktop Device Redirector Bus
pnputil /disable-device "ROOT\RDPBUS\0000"

rem Standard SATA AHCI Controller
pnputil /disable-device "PCI\VEN_1022&DEV_43F6&SUBSYS_10621B21&REV_01\6&6318A00&0&00680011"

rem System speaker
pnputil /disable-device "ACPI\PNP0800\4&D447ADA&0"

rem UMBus Root Bus Enumerator
pnputil /disable-device "ROOT\UMBUS\0000"

devmgmt.msc

pause

rem reg add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f

regedit

pause

reg add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f

start "" "D:\OneDrive\Downloads\OFF.bat"
