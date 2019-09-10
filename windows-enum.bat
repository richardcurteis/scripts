echo "Windows Enum Script for OS Troubleshooting"

echo "-- OS Version --"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

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

echo "-- Running Services --"
net start

echo "-- Check for Installed Drivers ---"
DRIVERQUERY

echo "-- Check for Installed Patches ---"
wmic qfe get Caption,Description,HotFixID,InstalledOn

echo "--- Searching for  files that contain 'password' in filename --"
dir /s *password*

echo "--- Searching for  files that contain 'password' with .txt extension --"
findstr /si password *.txt

echo "--- Find autostart files with unquoted servive path --"
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

echo "--- Check for AlwaysInstallElevated ---"
echo "HKCU"
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
echo "HKLM"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

echo "WMI Hotfixes"
wmic qfe list full
