echo "Windows Enum Script for OS Troubleshooting"
:: http://www.fuzzysecurity.com/tutorials/16.html
:: https://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html?m=1

echo "--- Hostname ---"
hostname

echo "-- OS Version --"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

echo "--- Users ---"
net users

echo "-- System Info --"
systeminfo

echo "-- Active Network Connections --"
netstat -ano

echo "-- Firewall State --"
netsh firewall show state

echo "-- Firewall Config --"
netsh firewall show config

echo "-- Scheduled Tasks --"
schtasks /query /fo LIST /v

echo "-- Process and Linked Services -- "
tasklist /SVC

echo "-- Startup Services --"
net start

echo "-- Check for Installed Drivers ---"
DRIVERQUERY

echo "-- Check for Installed Patches ---"
wmic qfe get Caption,Description,HotFixID,InstalledOn

echo "-- Check for Installed Patches ---"
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

echo "--- Searching for  files that contain 'password' in filename --"
dir /s *password*

echo "--- Searching for  files that contain 'password' with .txt extension --"
findstr /si password *.txt

echo "--- Search for Interesting XML --"
dir /s Groups.xml
dir /s Services.xml
dir /s Printers.xml
dir /s ScheduledTasks.xml
dir /s Drives.xml
dir /s DataSources.xml

echo "--- Find autostart files with unquoted servive path --"
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\\\" |findstr /i /v """

echo "--- Check for AlwaysInstallElevated ---"
echo "HKCU"
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
echo "HKLM"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

echo "--- Search Registry for 'password' ---"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query" HKCU\Software\SimonTatham\PuTTY\Sessions"


echo "--- Search Everywhere for files containing 'password'> *.xml *.ini *.txt ---"
findstr /si password *.xml *.ini *.txt *.xls *.xlsx 

echo "WMI Hotfixes"
wmic qfe list full

echo "---- Networking ---"
ipconfig /all
route print
arp -A
