@echo off
echo "--- Windows Enum Script for Windows Enummeration, PrivEsc and Exploitation ---"
:: http://www.fuzzysecurity.com/tutorials/16.html
:: https://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html?m=1
:: https://github.com/ihack4falafel/OSCP/blob/master/Windows/WinPrivCheck.bat
:: https://www.andreafortuna.org/2017/08/09/windows-command-line-cheatsheet-part-2-wmic/
:: https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/ 

SET cac=
:: Check if icacls.exe is installed/in PATH
for %%I in (icacls.exe) do (
    if not defined cac (
		:: Set as permissions binary: %cac%
		SET cac=%%~$PATH:I
    )
  )

SET access_chk_path=
:: Check if accesschk.exe is installed/in PATH
for %%A in (accesschk.exe) do (
    if not defined access_chk_path (
		:: Set as permissions binary: %cac%
		SET access_chk_path=%%~$PATH:A
    )
  )

:: If icacls.exe was NOT found, SET cacls.exe
if not defined cac (
      for %%X in (cacls.exe) do (
			SET cac=%%~$PATH:X
		)
    )
	
echo [!] %cac% SET for permissions checks...
    

echo ====================================PWK Keys Specific Check===============================
echo --- Check for PWK Keys --- 
dir /s proof.txt
dir /s network-secret.txt

echo =====================================OS General===========================================
echo --- Hostname --- 
hostname  

echo --- OS Version ---  
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"  /C:"System Type"

echo -- Envrionment Variables + PATH --- 
wmic environment list

echo --- System Info --- 
echo !!! Feed this output directly into WESNG !!!
echo https://github.com/bitsadmin/wesng
echo RUN: python wes.py --update
echo Copy output to systeminfo.txt
echo RUN: wes.py systeminfo.txt
systeminfo

echo --- AV Installed ---
wmic /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivirus installed

echo =====================================Users and Groups=====================================
echo --- Username ---
echo %username% 2>NUL
whoami 2>NUL
echo %userprofile% 2>NUL

echo --- Current Users Privileges ---
whoami /priv

accesschk.exe /accepteula -q -a *

echo --- Anyone Else Logged In? ---
qwinsta

echo --- Groups On System ---
net localgroup

echo --- Any Users in Administrators Group? ---
net localgroup administrators

echo --- Users --- 
net users 

echo -- List User Accounts ---
wmic useraccount list

echo --- List Groups ---
wmic group list

echo --- Sysaccount List ---
wmic sysaccount list

echo --- Identify any local system accounts that are enabled ---
wmic USERACCOUNT WHERE "Disabled=0 AND LocalAccount=1" GET Name

echo --- Rgistry Entries for Autologon ---
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

echo -- Password Policy ---
net group

echo --- Credential Manager:  List stored credentials ---
cmdkey /list
echo C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
echo C:\Users\username\AppData\Roaming\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\

echo ======================================PERMISSIONS=========================================
echo --- Access to SAM and SYSTEM Files ---
echo https://superuser.com/questions/322423/explain-the-output-of-%cac%-exe-line-by-line-item-by-item
echo https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/%cac%
echo
SET system_root=echo %SYSTEMROOT%
%cac% %system_root%\repair\SAM
%cac% %system_root%\System32\config\RegBack\SAM
%cac% %system_root%\System32\config\SAM
%cac% %system_root%\repair\system
%cac% %system_root%\System32\config\SYSTEM
%cac% %system_root%\System32\config\RegBack\system

echo --- Full Permissions for Everyone or Users on Program Folders? ---
%cac% "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
%cac% "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

%cac% "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
%cac% "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 

echo --- Modify Permissions for Everyone or Users on Program Folders? ---
%cac% "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
%cac% "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

%cac% "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
%cac% "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 

echo --- Services in Registry: Insecure Registry Permissions? ---
echo https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
echo Need more research here
echo req query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services

echo --- Accesschk.exe ---

echo --- What are the running processes/services on the system? Is there an inside service not exposed? If so, can we open it? ---
tasklist /svc
tasklist /v
net start
sc query

echo --- Any weak service permissions? Can we reconfigure anything? ---
echo Checking for accesschk.exe....

:: If accesschk.exe was found, run checks
if defined access_chk_path (
      for %%X in (cacls.exe) do (
			echo --- AccessChk Checks ---
			echo --- Current Users Privileges ---
			accesschk.exe /accepteula -q -a *
			accesschk.exe -uwcqv "Everyone" *
			accesschk.exe -uwcqv "Authenticated Users" *
			accesschk.exe -uwcqv "Users" *
			
			echo --- Service Permissions for Running Services ---
			sc query state= all | find "SERVICE_NAME" > service_list.txt

			FOR /F "tokens=2 delims= " %%s in (service_list.txt) DO (
			echo %%s >> services.txt
				)

			FOR /F "tokens=*" %%s IN (services.txt) DO (
			sc qc %%s >> service_info.txt
			accesschk.exe -accepteula -ucqv %%B >> service_info.txt
			)

			del service_list.txt
			del services.txt
		)
    ) else (
			echo accesschk.exe not found on host
			sc query state= all | find "SERVICE_NAME"
		)

echo ======================================Mimikatz============================================
echo Mimikatz Placeholder

echo ======================================Incognito===========================================
echo Incognito Placeholder

echo ======================================GPO=================================================

echo --- GPO User ---
gpresult /Scope User /v 

echo --- GPO Computer ---
gpresult /Scope Computer /v 

echo ====================================Shares================================================
echo --- List Shares ---
wmic share list

echo ====================================Firewall===============================================
echo --- Current Profile --- 
netsh advfirewall show currentprofile

echo --- All Profiles --- 
netsh advfirewall show allprofiles

echo --- Show All Rules. Be verbose ---
netsh advfirewall firewall show rule name=all verbose

echo ====================================Services, Tasks and Processes==========================
echo --- What Scheduled Tasks are there? Anything custom implemented? --- 
schtasks /query /fo LIST 2>nul | findstr TaskName
dir C:\windows\tasks

echo --- Process and Linked Services --- 
tasklist /SVC 

echo --- Processes and Linked DLLs ---
tasklist /m

echo --- Startup Services --- 
net start 

echo --- Startup List ---
echo --- What commands are run at startup? ---
wmic startup get caption,command

echo --- Other Startup Checks ---
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"

echo =========================================Software and Patching===================================

echo --- Installed Software ---
wmic product get Name, Version
echo --- Check for Installed Patches ---- 
wmic qfe get Caption,Description,HotFixID,InstalledOn 

echo WMI Hotfixes 
wmic qfe list full 

echo --- Check for Installed Drivers ---- 
DRIVERQUERY 

echo --- Reference Exploits against Patches ---
echo Reference Below chart to check for false positives.


echo #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo #    Exploits Index    | 2K      | XP    | 2K3   | 2K8     | Vista   | 7   |                           Title                       |
echo #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB2592799 | MS11-080 |    X    | SP3   | SP3   |    X    |    X    |  X  | afd.sys                  - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB3143141 | MS16-032 |    X    |   X   |   X   | SP1/2   | SP2     | SP1 | Secondary Logon          - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB2393802 | MS11-011 |    X    | SP2/3 | SP2   | SP2     | SP1/2   | SP0 | WmiTraceMessageVa        - Local privilege Escalation | 
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB982799  | MS10-059 |    X    |   X   |   X   | ALL     | ALL     | SP0 | Chimichurri              - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB979683  | MS10-021 | SP4     | SP2/3 | SP2   | SP2     | SP0/1/2 | SP0 | Windows Kernel           - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB2305420 | MS10-092 |    X    |   X   |   X   | SP0/1/2 | SP1/2   | SP0 | Task Scheduler           - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB981957  | MS10-073 |    X    | SP2/3 | SP2   | SP2     | SP1/2   | SP0 | Keyboard Layout          - Local privilege Escalation | 
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB4013081 | MS17-017 |    X    |   X   |   X   | SP2     | SP2     | SP1 | Registry Hive Loading    - Local privilege Escalation | 
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB977165  | MS10-015 | ALL     | ALL   | ALL   | ALL     | ALL     | ALL | User Mode to Ring        - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB941693  | MS08-025 | SP4     | SP2   | SP1/2 | SP0     | SP0/1   |  X  | win32k.sys               - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB920958  | MS06-049 | SP4     |   X   |   X   |    X    |    X    |  X  | ZwQuerySysInfo           - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB914389  | MS06-030 | ALL     | SP2   |   X   |    X    |    X    |  X  | Mrxsmb.sys               - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB908523  | MS05-055 | SP4     |   X   |   X   |    X    |    X    |  X  | APC Data-Free            - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB890859  | MS05-018 | SP3/4   | SP1/2 |   X   |    X    |    X    |  X  | CSRSS                    - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB842526  | MS04-019 | SP2/3/4 |   X   |   X   |    X    |    X    |  X  | Utility Manager          - Local privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB835732  | MS04-011 | SP2/3/4 | SP0/1 |   X   |    X    |    X    |  X  | LSASS service BoF        - Remote Code Execution      | 
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB841872  | MS04-020 | SP4     |   X   |   X   |    X    |    X    |  X  | POSIX                    - Local Privilege Escalation |
echo #----------------------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB2975684 | MS14-040 |    X    |   X   | SP2   | SP2     | SP2     | SP1 | afd.sys Dangling Pointer - Local Privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB3136041 | MS16-016 |    X    |   X   |   X   | SP1/2   | SP2     | SP1 | WebDAV to Address        - Local Privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------# 
echo # KB3057191 | MS15-051 |    X    |   X   | SP2   | SP2     | SP2     | SP1 | win32k.sys               - Local Privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#
echo # KB2989935 | MS14-070 |    X    |   X   | SP2   |    X    |    X    |  X  | TCP/IP                   - Local Privilege Escalation |
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------# 
echo # KB2503665 | MS11-046 |    X    |  SP3  | SP2   |  SP1/2  |  SP1/2  | SP1 | 'afd.sys'                - Local Privilege Escalation |  
echo #-----------#----------#---------#-------#-------#---------#---------#-----#-------------------------------------------------------#

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

echo ===========================================================================================
echo --- Wildcard search for  files that contain *pass* in filename -- 
dir /s *pass* *.xml *.ini *.txt *.dat *.msg 2>nul

echo ===========================================================================================
echo --- Search Everywhere for files containing contents, 'pass*' --- 
echo --- Formats checked: *.xml *.ini *.txt *.dat *.msg---
echo Removed *.txt
findstr /si pass* *.xml *.ini *.dat *.msg 2>nul
:: Nuclear Option
:: findstr /si pass* *.*

echo ===========================================================================================
echo --- Search for Interesting XML --- 
dir /s Groups.xml 
dir /s Services.xml 
dir /s Printers.xml 
dir /s ScheduledTasks.xml 
dir /s Drives.xml 
dir /s DataSources.xml 

echo ===========================================================================================
echo --- Sysprep or Unattended Files ---
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir /s *pass* == *vnc* == *.config* 2>nul

echo --- Search Everywhere for Sysprep or Unattended Files ---
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul

echo ===========================================================================================
echo --- Find autostart files with unquoted service path --- 
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\\\" |findstr /i /v """  

echo ===========================================================================================
echo --- Check for AlwaysInstallElevated --- 
echo *.MSI Install as SYSTEM
echo This will only work if both registry keys contain "AlwaysInstallElevated" with DWORD values of 1.
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 

echo ===========================================================================================
echo --- Search Registry for 'password' --- 
reg query HKLM /f password /t REG_SZ /s 
reg query HKCU /f password /t REG_SZ /s 
reg query HKU /f password /t REG_SZ /s
reg query "HKCU\Software\ORL\WinVNC3\Password" 
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 
reg query "HKCU\Software\%username%\PuTTY\Sessions" 
reg query "HKCU\Software\administrator\PuTTY\Sessions" 

echo =========================================Networking=========================================
echo ---- Ipconfig --- 
ipconfig /all 

echo --- Route ---
route print 

echo --- ARP ---
arp -A 

echo --- Active Network Connections ---  
netstat -ano  

echo --- Hosts ---
type C:\WINDOWS\System32\drivers\etc\hosts

echo --- Interface Configurations
netsh dump

echo --- SNMP Configurations ---
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s

echo =========================================Web Server Checks====================================
echo --- What’s in inetpub? Any hidden directories? web.config files? ---
dir /a C:\inetpub\
dir /s web.config
type C:\Windows\System32\inetsrv\config\applicationHost.config > server-checks.txt

echo --- IIS Logs ---
echo --- need to check if this will run without explicit dates??? ---
type C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log >> server-checks.txt
type C:\inetpub\logs\LogFiles\W3SVC2\u_ex[YYMMDD].log >> server-checks.txt
type C:\inetpub\logs\LogFiles\FTPSVC1\u_ex[YYMMDD].log >> server-checks.txt
type C:\inetpub\logs\LogFiles\FTPSVC2\u_ex[YYMMDD].log >> server-checks.txt

echo --- XAMPP, Apache, or PHP installed? Any there any configuration files?--- 
dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf

echo --- Apache Web Logs --- 
dir /s access.log error.log
