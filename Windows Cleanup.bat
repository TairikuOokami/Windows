rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!

rem Driver Store Explorer - https://github.com/lostindark/DriverStoreExplorer/releases
rem HiBit Uninstaller - http://hibitsoft.ir
rem Wise Disk Cleaner - http://www.wisecleaner.com/wise-disk-cleaner.html
rem Wise Registry Cleaner - http://www.wisecleaner.com/wise-registry-cleaner.html
rem Windows Drivers - https://www.catalog.update.microsoft.com/Home.aspx
rem Windows Repair Toolbox - https://windows-repair-toolbox.com

rem Disable Reserved Storage (7GB)
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

fsutil usn deletejournal /d /n c:
chkdsk /scan
ipconfig /flushdns
winget source update

taskkill /im msi.exe /f
taskkill /im wuauclt.exe /f
taskkill /im sihclient.exe /f
taskkill /im TiWorker.exe /f
taskkill /im trustedinstaller.exe /f
taskkill /im MoUsoCoreWorker.exe /f
taskkill /im UsoClient.exe /f
taskkill /im usocoreworker.exe /f
net stop bits /y
net stop cryptSvc /y
net stop DoSvc /y
net stop EventLog /y
net stop msiserver /y
net stop UsoSvc /y
net stop winmgmt /y
winmgmt /salvagerepository
net stop wuauserv /y
schtasks /End /TN "\Microsoft\Windows\Wininet\CacheTask"

takeown /f "%WINDIR%\winsxs\pending.xml" /a
icacls "%WINDIR%\winsxs\pending.xml" /grant:r Administrators:F /c
del "%WINDIR%\winsxs\pending.xml" /s /f /q

del "C:\$Recycle.bin" /s /f /q
del "D:\$Recycle.bin" /s /f /q
del "E:\$Recycle.bin" /s /f /q
del "Z:\$Recycle.bin" /s /f /q

del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%LocalAppData%\Microsoft\Windows\WebCache" /s /f /q
del "%LocalAppData%\Temp" /s /f /q
rd "%ProgramData%\Applications" /s /q
rd "%ProgramData%\Package Cache" /s /q
rd "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
rd "%SystemDrive%\$GetCurrent" /s /q
rd "%SystemDrive%\$SysReset" /s /q
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q
rd "%SystemDrive%\$WinREAgent" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
rd "%SystemDrive%\Recovery" /s /q
del "%temp%" /s /f /q
del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
del "%WINDIR%\SoftwareDistribution\Download" /s /f /q
del "%WINDIR%\System32\LogFiles" /s /f /q
del "%WINDIR%\System32\winevt\Logs" /s /f /q
del "%WINDIR%\Temp" /s /f /q
del "%WINDIR%\WinSxS\Backup" /s /f /q

rem https://forums.mydigitallife.net/threads/windows-10-hotfix-repository.57050/page-622#post-1655591
rem https://forums.mydigitallife.net/threads/which-windows-10-services-you-guys-disable.75202/page-6#post-1742386
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v DisableRemovePayload /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v DisableWerReporting /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v EnableDpxLog /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v LCUReoffer /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v ResetManifestCache /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "CBSLogCompress" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "CompressBackups" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "CompressMutables" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableComponentBackups" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableResetbase" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableWerReporting" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "LCUReoffer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "NTFSCompressPayload" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "NumCBSPersistLogs" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "PreserveFileCompressionState" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "ReofferUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "SupersededActions" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "TransientManifestCache" /t "REG_DWORD" /d "1" /f

rem DISM /Online /Cleanup-Image /AnalyzeComponentStore
rem fsutil storagereserve query C:
rem vssadmin list shadowstorage
vssadmin delete shadows /for=c: /all /quiet
DISM /Get-mountedwiminfo
DISM /Cleanup-mountpoints
DISM /Cleanup-wim
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Content Indexer Cleaner" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Device Driver Packages" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder" /v "StateFlags6553" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" /v "StateFlags6553" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v "Autorun" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v "StateFlags6553" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
rem cleanmgr /sageset:6553
cleanmgr /sagerun:6553

start ms-settings:storagepolicies

rem Cleanup done, you can close this window!
timeout -1

rem ======================================= OPTIONAL =======================================

rem Perform a Single Time Ultra Compress, it has to be redone regularly (it can cause lagging in Windows)
rem compact /c /i /q /f /exe:lzx /s:C:\Windows

rem https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image?view=windows-11
rem https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e
rem DISM /Online /Cleanup-Image /ScanHealth
rem DISM /Online /Cleanup-Image /CheckHealth
DISM /Online /Cleanup-Image /RestoreHealth
SFC /SCANNOW

pause

rem Uninstall reinstalled MS Apps
rem C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle  | Where-Object {$_.NonRemovable -eq $False} | Select-Object Name, PackageFullName"
start "" /wait C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "Get-AppxPackage -AllUsers -PackageTypeFilter Bundle -Name "MicrosoftWindows.Client.WebExperience" | Remove-AppxPackage -AllUsers"

rem Open Explorer - Choose the desired View - View - Options - View - Apply to Folders - OK - Close/Restart Explorer ASAP
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags" /f
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\BagMRU" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f

reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "IconStreams" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "PastIconsStream" /f

rem Backup Apps
winget export -o D:\OneDrive\Setup\winget.txt

start "" /wait "%ProgramFiles(x86)%\Wise\Wise Disk Cleaner\WiseDiskCleaner.exe" -a -all
start "" /wait "%ProgramFiles(x86)%\Wise\Wise Registry Cleaner\WiseRegCleaner.exe" -a -all

rem Backup Browsers (Flags/Settings)
taskkill /im brave.exe /f
taskkill /im firefox.exe /f
taskkill /im librewolf.exe /f
taskkill /im msedge.exe /f
taskkill /im tor.exe /f

rd "D:\OneDrive\Soft\Brave" /s /q
rd "D:\OneDrive\Soft\Edge" /s /q
rd "D:\OneDrive\Soft\Librewolf" /s /q

xcopy "Z:\Brave" "D:\OneDrive\Soft\Brave" /s /i /y
xcopy "Z:\Edge" "D:\OneDrive\Soft\Edge" /s /i /y
xcopy "Z:\Librewolf" "D:\OneDrive\Soft\Librewolf" /s /i /y

rem Backup Custom Settings
xcopy "%AppData%\SystemInformer\settings.xml" "D:\OneDrive\Setup\Users\Tairi\AppData\Roaming\SystemInformer\settings.xml" /y
xcopy "%AppData%\Wise Disk Cleaner\Config.ini" "D:\OneDrive\Setup\Users\Tairi\AppData\Roaming\Wise Disk Cleaner\Config.ini" /y
xcopy "%AppData%\Wise Registry Cleaner\Config.ini" "D:\OneDrive\Setup\Users\Tairi\AppData\Roaming\Wise Registry Cleaner\Config.ini" /y

rem Remove Old Drivers
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
start "" /wait "D:\OneDrive\Soft\Windows Repair Toolbox\Downloads\Custom Tools\Added Custom Tools\Rapr.exe"

rem Trim
start "" /wait "%ProgramFiles(x86)%\Wise\Wise Disk Cleaner\WiseDiskCleaner.exe"
start "" /wait "%ProgramFiles%\Kingston_SSD_Manager\KSM_Gen15.exe"

rem Reinstall WFC broken after cleanup
start "" /wait "D:\OneDrive\Setup\wfc6setup.exe"
start "" "C:\Program Files\Malwarebytes\Windows Firewall Control\wfcUI.exe"

rem Create System Backup
sc config "HasleoBackupSuiteService" start= demand
sc config "HasleoImageMountService" start= demand
net start "HasleoBackupSuiteService"
net start "HasleoImageMountService"
start "" /wait "C:\Program Files\Hasleo\Hasleo Backup Suite\bin\BackupMainUI.exe"
