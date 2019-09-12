@echo off
rem "--- Windows Enum Script for Windows Enummeration, PrivEsc and Exploitation ---"
:: http://www.fuzzysecurity.com/tutorials/16.html
:: https://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html?m=1
:: https://github.com/ihack4falafel/OSCP/blob/master/Windows/WinPrivCheck.bat
:: https://www.andreafortuna.org/2017/08/09/windows-command-line-cheatsheet-part-2-wmic/

rem ====================================PWK Keys Specific Check===============================
rem --- Check for PWK Keys --- 
findstr /si proof *.txt
findstr /si network-secret *.txt

rem =====================================OS General===========================================
rem --- Username ---
echo %username% 2>NUL
whoami 2>NUL
echo %userprofile% 2>NUL

rem --- Hostname --- 
hostname  

rem --- OS Version ---  
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"  /C:"System Type"

rem -- Envrionment Variables + PATH --- 
wmic environment list

rem --- System Info --- 
rem !!! Feed this output directly into WESNG !!!
rem https://github.com/bitsadmin/wesng
rem RUN: python wes.py --update
rem Copy output to systeminfo.txt
rem RUN: wes.py systeminfo.txt
systeminfo

rem =====================================Users and Groups=====================================
rem --- Users --- 
net users 

rem -- List User Accounts ---
wmic useraccount list

rem --- List Groups ---
wmic group list

--- Sysaccount List ---
wmic sysaccount list

rem --- Identify any local system accounts that are enabled ---
wmic USERACCOUNT WHERE "Disabled=0 AND LocalAccount=1" GET Name

rem -- Password Policy ---
net group


rem ====================================Shares================================================
rem --- List Shares ---
wmic share list

rem ====================================Firewall===============================================
rem --- Current Profile --- 
netsh advfirewall show currentprofile

rem --- All Profiles --- 
netsh advfirewall show allprofiles

rem --- Show All Rules. Be verbose ---
netsh advfirewall firewall show rule name=all verbose

rem ====================================Services, Tasks and Processes==========================
rem --- Scheduled Tasks --- 
schtasks /query /fo LIST /v 

rem --- Process and Linked Services --- 
tasklist /SVC 

rem --- Processes and Linked DLLs ---
tasklist /m

rem --- Startup Services --- 
net start 

rem --- Startup List ---
wmic startup list full

rem --- Service Permissions for Running Services ---
sc query state= all | find "SERVICE_NAME" > service_list.txt

FOR /F "service=2 delims= " %%A in (service_list.txt) DO (
	echo %%A >> services.txt
)

FOR /F "service=*" %%B IN (services.txt) DO (
	sc qc %%B >> service_info.txt
	accesschk64.exe -accepteula -ucqv %%B >> service_info.txt
)

del service_list.txt
del services.txt

rem =========================================Software and Patching===================================

rem --- Installed Software ---
wmic product get Name, Version
rem --- Check for Installed Patches ---- 
wmic qfe get Caption,Description,HotFixID,InstalledOn 

rem WMI Hotfixes 
wmic qfe list full 

rem --- Check for Installed Drivers ---- 
DRIVERQUERY 

rem --- Reference Exploits against Patches ---
rem Reference Below chart to check for false positives.


rem #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem #    Exploits Index    | 2K      | XP    | 2K3   | 2K8     | Vista   | 7   |                           Title                       |
rem #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2592799 | MS11-080 |    X    | SP3   | SP3   |    X    |    X    |  X  | afd.sys                  - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB3143141 | MS16-032 |    X    |   X   |   X   | SP1/2   | SP2     | SP1 | Secondary Logon          - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2393802 | MS11-011 |    X    | SP2/3 | SP2   | SP2     | SP1/2   | SP0 | WmiTraceMessageVa        - Local privilege Escalation | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB982799  | MS10-059 |    X    |   X   |   X   | ALL     | ALL     | SP0 | Chimichurri              - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB979683  | MS10-021 | SP4     | SP2/3 | SP2   | SP2     | SP0/1/2 | SP0 | Windows Kernel           - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2305420 | MS10-092 |    X    |   X   |   X   | SP0/1/2 | SP1/2   | SP0 | Task Scheduler           - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB981957  | MS10-073 |    X    | SP2/3 | SP2   | SP2     | SP1/2   | SP0 | Keyboard Layout          - Local privilege Escalation | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB4013081 | MS17-017 |    X    |   X   |   X   | SP2     | SP2     | SP1 | Registry Hive Loading    - Local privilege Escalation | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB977165  | MS10-015 | ALL     | ALL   | ALL   | ALL     | ALL     | ALL | User Mode to Ring        - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB941693  | MS08-025 | SP4     | SP2   | SP1/2 | SP0     | SP0/1   |  X  | win32k.sys               - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB920958  | MS06-049 | SP4     |   X   |   X   |    X    |    X    |  X  | ZwQuerySysInfo           - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB914389  | MS06-030 | ALL     | SP2   |   X   |    X    |    X    |  X  | Mrxsmb.sys               - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB908523  | MS05-055 | SP4     |   X   |   X   |    X    |    X    |  X  | APC Data-Free            - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB890859  | MS05-018 | SP3/4   | SP1/2 |   X   |    X    |    X    |  X  | CSRSS                    - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB842526  | MS04-019 | SP2/3/4 |   X   |   X   |    X    |    X    |  X  | Utility Manager          - Local privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB835732  | MS04-011 | SP2/3/4 | SP0/1 |   X   |    X    |    X    |  X  | LSASS service BoF        - Remote Code Execution      | 
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB841872  | MS04-020 | SP4     |   X   |   X   |    X    |    X    |  X  | POSIX                    - Local Privilege Escalation |
rem #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2975684 | MS14-040 |    X    |   X   | SP2   | SP2     | SP2     | SP1 | afd.sys Dangling Pointer - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB3136041 | MS16-016 |    X    |   X   |   X   | SP1/2   | SP2     | SP1 | WebDAV to Address        - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------# 
rem # KB3057191 | MS15-051 |    X    |   X   | SP2   | SP2     | SP2     | SP1 | win32k.sys               - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
rem # KB2989935 | MS14-070 |    X    |   X   | SP2   |    X    |    X    |  X  | TCP/IP                   - Local Privilege Escalation |
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------# 
rem # KB2503665 | MS11-046 |    X    |  SP3  | SP2   |  SP1/2  |  SP1/2  | SP1 | 'afd.sys'                - Local Privilege Escalation |  
rem #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2592799" | find /i "KB2592799" 1>NUL
IF not errorlevel 1 (
	
  echo MS11-080 patch is installed :(

) ELSE (

  echo MS11-080 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3143141" | find /i "KB3143141" 1>NUL
IF not errorlevel 1 (
	
  echo MS16-032 patch is installed :(

) ELSE (

  echo MS16-032 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2393802" | find /i "KB2393802" 1>NUL
IF not errorlevel 1 (
	
  echo MS11-011 patch is installed :(

) ELSE (

  echo MS11-011 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB982799" | find /i "KB982799" 1>NUL
IF not errorlevel 1 (
	
  echo MS10-059 patch is installed :(

) ELSE (

  echo MS10-059 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB979683" | find /i "KB979683" 1>NUL
IF not errorlevel 1 (
	
  echo MS10-021 patch is installed :(

) ELSE (

  echo MS10-021 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2305420" | find /i "KB2305420" 1>NUL
IF not errorlevel 1 (
	
  echo MS10-092 patch is installed :(

) ELSE (

  echo MS10-092 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB981957" | find /i "KB981957" 1>NUL
IF not errorlevel 1 (
	
  echo MS10-073 patch is installed :(

) ELSE (

  echo MS10-073 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB4013081" | find /i "KB4013081" 1>NUL
IF not errorlevel 1 (
	
  echo MS17-017 patch is installed :(

) ELSE (

  echo MS17-017 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB977165" | find /i "KB977165" 1>NUL
IF not errorlevel 1 (
	
  echo MS10-015 patch is installed :(

) ELSE (

  echo MS10-015 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB941693" | find /i "KB941693" 1>NUL
IF not errorlevel 1 (
	
  echo MS08-025 patch is installed :(

) ELSE (

  echo MS08-025 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB920958" | find /i "KB920958" 1>NUL
IF not errorlevel 1 (
	
  echo MS06-049 patch is installed :(

) ELSE (

  echo MS06-049 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB914389" | find /i "KB914389" 1>NUL
IF not errorlevel 1 (
	
  echo MS06-030 patch is installed :(

) ELSE (

  echo MS06-030 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB908523" | find /i "KB908523" 1>NUL
IF not errorlevel 1 (
	
  echo MS05-055 patch is installed :(

) ELSE (

  echo MS05-055 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB890859" | find /i "KB890859" 1>NUL
IF not errorlevel 1 (
	
  echo MS05-018 patch is installed :(

) ELSE (

  echo MS05-018 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB842526" | find /i "KB842526" 1>NUL
IF not errorlevel 1 (
	
  echo MS04-019 patch is installed :(

) ELSE (

  echo MS04-019 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB835732" | find /i "KB835732" 1>NUL
IF not errorlevel 1 (
	
  echo MS04-011 patch is installed :(

) ELSE (

  echo MS04-011 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB841872" | find /i "KB841872" 1>NUL
IF not errorlevel 1 (
	
  echo MS04-020 patch is installed :(

) ELSE (

  echo MS04-020 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2975684" | find /i "KB2975684" 1>NUL
IF not errorlevel 1 (
	
  echo MS14-040 patch is installed :(

) ELSE (

  echo MS14-040 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3136041" | find /i "KB3136041" 1>NUL
IF not errorlevel 1 (
	
  echo MS16-016 patch is installed :(

) ELSE (

  echo MS16-016 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3057191" | find /i "KB3057191" 1>NUL
IF not errorlevel 1 (
	
  echo MS15-051 patch is installed :(

) ELSE (

  echo MS15-051 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2989935" | find /i "KB2989935" 1>NUL
IF not errorlevel 1 (
	
  echo MS14-070 patch is installed :(

) ELSE (

  echo MS14-070 patch is NOT installed! 

)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2503665" | find /i "KB2503665" 1>NUL
IF not errorlevel 1 (
	
  echo MS11-046 patch is installed :(

) ELSE (

  echo MS11-046 patch is NOT installed! 

)

rem ===========================================================================================
rem --- Wildcard search for  files that contain *pass* in filename -- 
dir /s *pass* 

rem ===========================================================================================
rem --- Search Everywhere for files containing 'pass*' --- 
rem !!! May need to edit this as it will return a LOT of results !!!
rem --- Formats checked: *.xml *.ini *.txt *.xls *.xlsx *.doc *.docx *.bat *.nt *.wsf *.vb *.ps1 *.json *.conf *.csv *.cmd *.msg---
findstr /si pass* *.xml *.ini *.txt *.xls *.xlsx *.doc *.docx *.bat *.nt *.wsf *.vb *.ps1 *.json *.conf *.csv *.cmd *.msg
:: Nuclear Option
:: findstr /si pass* *.*

rem ===========================================================================================
rem --- Search for Interesting XML --- 
dir /s Groups.xml 
dir /s Services.xml 
dir /s Printers.xml 
dir /s ScheduledTasks.xml 
dir /s Drives.xml 
dir /s DataSources.xml 

rem ===========================================================================================
rem --- Clear-text/base64 Passwords ---
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir /s *cred*
dir /s *vnc*
dir /s *.config

rem ===========================================================================================
rem --- Find autostart files with unquoted service path --- 
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\\\" |findstr /i /v """  

rem ===========================================================================================
rem --- Check for AlwaysInstallElevated --- 
rem *.MSI Install as SYSTEM
rem This will only work if both registry keys contain "AlwaysInstallElevated" with DWORD values of 1.
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 

rem ===========================================================================================
rem --- Search Registry for 'password' --- 
reg query HKLM /f password /t REG_SZ /s 
reg query HKCU /f password /t REG_SZ /s 
reg query "HKCU\Software\ORL\WinVNC3\Password" 
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 
reg query "HKCU\Software\%username%\PuTTY\Sessions" 
reg query "HKCU\Software\administrator\PuTTY\Sessions" 

rem ===========================================================================================
rem ---- Networking --- 
ipconfig /all 
route print 
arp -A 

rem ===========================================================================================
rem --- Active Network Connections ---  
netstat -ano  
