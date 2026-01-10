rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!


rem NOTE: It is highly recommended to install MS Defender Platform Updates sometimes (monthly) because they affect Windows protection as well, like LSA and System Guard!
rem MS Defender Platform/Signatures Updates - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates?view=o365-worldwide
rem Windows Security Platform Updates automatically - https://support.microsoft.com/en-us/topic/windows-security-update-a6ac7d2e-b1bf-44c0-a028-41720a242da3
rem Search a version number to update Defender manually, like: https://www.catalog.update.microsoft.com/Search.aspx?q=4.18.23110.3
rem Enable Defender - update - restart - disable Defender - https://github.com/TairikuOokami/Windows/blob/main/Microsoft%20Defender%20Enable.bat

rem Disable Tamper and Real Time Protection in Defender - RESTART!
rem start windowsdefender:
rem Disable Real Time Protection in Defender - Run "Microsoft Defender Disable.bat" - TWICE - RESTART!
rem Run "Microsoft Defender Disable.bat" again - TWICE - RESTART!

rem Alternatively run in Safe Mode
rem Run - msconfig - Boot - Safe Boot - Minimal - Restart
rem Run "MD Disable.bat" TWICE - RESTART!
rem Run - msconfig - General - Normal Startup

rem https://www.elevenforum.com/t/turn-on-or-off-tamper-protection-for-microsoft-defender-antivirus-in-windows-11.3973
rem reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f

rem Disable System Guard Runtime Monitor Broker (when disabled, it might cause BSOD Critical Process Died)
rem reg add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f

rem Disable Windows Defender Security Center
rem reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f

rem 1 - Antivirus Disabled Notification
reg add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f

rem 0 - Security and Maitenance Notification
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f

rem 1 - Disable Real-time protection
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableLocalAdminMerge" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSpecialRunningModes" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIntrusionPreventionSystem" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableOnAccessProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideRealtimeScanDirection" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

rem 0 - Disable Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f

rem Disable Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

rem Disable systray icon
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f

rem Remove context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f

rem Disable services (it will stop WdFilter.sys as well, better not to disable the driver by itself)
rem reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
rem MDCoreSvc has become more persistent and runs when disabled, but it does not interfere
reg add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

rem ======================================= OPTIONAL =======================================

rem Web Threat Defense Service (Phishing protection)
rem sc config webthreatdefsvc start= disabled

rem Web Threat Defense User Service (Phishing protection)
rem sc config webthreatdefusersvc start= disabled

rem Off - Disable Windows SmartScreen / On - Enable Windows SmartScreen 
rem reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f

rem 0 - Disable SmartScreen Filter in Microsoft Edge / 1 - Enable
rem reg add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f

rem 0 - Disable SmartScreen PUA in Microsoft Edge / 1 - Enable
rem reg add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d "0" /f

rem 0 - Disable Windows SmartScreen for Windows Store Apps / 1 - Enable
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f

rem Remove Smartscreen (to restore run "sfc /scannow")
rem takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
rem icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
rem taskkill /im smartscreen.exe /f
rem del "%WinDir%\System32\smartscreen.exe" /s /f /q

rem Disable Stupid Smart App Control blocking legitimate apps like VisualC++ and DX9 / ONCE DISABLED, IT CAN NOT BE ENABLED!
rem reg add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f

rem Last Tested on Windows 11 Home 28020.1362
rem Microsoft Defender Platform Version 4.18.26010.2 (10-Jan-2026
rem Before - https://ibb.co/CpBqXbfS / After - https://ibb.co/MD1DgF5s

pause
