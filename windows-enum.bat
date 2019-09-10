echo "Windows Enum Script for Windows Enum"
:: http://www.fuzzysecurity.com/tutorials/16.html
:: https://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html?m=1

echo "--- Hostname ---" > report.txt
hostname  >> report.txt

echo "-- OS Version --"  >> report.txt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt

echo "--- Users ---" >> report.txt
net users >> report.txt

echo "-- System Info --" >> report.txt
systeminfo >> report.txt

echo "-- Active Network Connections --"  >> report.txt
netstat -ano  >> report.txt

echo "-- Firewall State --"  >> report.txt
netsh firewall show state >> report.txt

echo "-- Firewall Config --" >> report.txt
netsh firewall show config >> report.txt

echo "-- Scheduled Tasks --" >> report.txt
schtasks /query /fo LIST /v >> report.txt

echo "-- Process and Linked Services -- " >> report.txt
tasklist /SVC >> report.txt

echo "-- Startup Services --" >> report.txt
net start >> report.txt

echo "-- Check for Installed Drivers ---" >> report.txt
DRIVERQUERY >> report.txt

echo "-- Check for Installed Patches ---" >> report.txt
wmic qfe get Caption,Description,HotFixID,InstalledOn >> report.txt

echo "-- Check for Installed Patches ---" >> report.txt
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.." >> report.txt

echo "--- Searching for  files that contain 'password' in filename --" >> report.txt
dir /s *password* >> report.txt

echo "--- Searching for  files that contain 'password' with .txt extension --" >> report.txt
findstr /si password *.txt >> report.txt

echo "--- Search for Interesting XML --" >> report.txt
dir /s Groups.xml >> report.txt
dir /s Services.xml >> report.txt
dir /s Printers.xml >> report.txt
dir /s ScheduledTasks.xml >> report.txt
dir /s Drives.xml >> report.txt
dir /s DataSources.xml >> report.txt

echo "--- Find autostart files with unquoted servive path --" >> report.txt
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\\\" |findstr /i /v """  >> report.txt

echo "--- Check for AlwaysInstallElevated ---" >> report.txt
echo "HKCU" >> report.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> report.txt
echo "HKLM" >> report.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> report.txt

echo "--- Search Registry for 'password' ---" >> report.txt
reg query HKLM /f password /t REG_SZ /s >> report.txt
reg query HKCU /f password /t REG_SZ /s >> report.txt
reg query "HKCU\Software\ORL\WinVNC3\Password" >> report.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" >> report.txt
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> report.txt
reg query" HKCU\Software\SimonTatham\PuTTY\Sessions" >> report.txt


echo "--- Search Everywhere for files containing 'password'> *.xml *.ini *.txt ---" >> report.txt
findstr /si password *.xml *.ini *.txt *.xls *.xlsx  >> report.txt

echo "WMI Hotfixes" >> report.txt
wmic qfe list full >> report.txt

echo "---- Networking ---" >> report.txt
ipconfig /all >> report.txt
route print >> report.txt
arp -A >> report.txt
