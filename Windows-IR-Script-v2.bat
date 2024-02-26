
@echo off
echo ##  Script for gathering windows system artifacts for Digital Forensics and Incidence Response activities  ##
echo Do run this script from Admin command prompt on the same path where this script is located.
echo ****************Script running*****************
echo Please wait for few minutes until the "End of script" message is displayed in this prompt.

echo  Script was executed on Date:%date% and Time:%time% >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt


echo #------------------------------------- Prefetch Files copied to IR-Collection folder -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
robocopy C:\Windows\Prefetch\  .\IR-Collection\Prefetch
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Windows Log files copied to IR-Collection folder-------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
robocopy C:\Windows\System32\winevt\Logs\  .\IR-Collection\Logs
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Windows Log files copied to IR-Collection folder-------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
robocopy  C:\Windows\System32\WDI\LogFiles\  .\IR-Collection\ETL-Logs\
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Amcache Files copied to execution path -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
RawCopy.exe /FileNamePath:C:\Windows\appcompat\Programs\Amcache.hve
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Windows SRUM file copied to execution path -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
RawCopy.exe /FileNamePath:C:\Windows\System32\sru\SRUDB.dat
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Registry files copied to execution path-------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SYSTEM
RawCopy.exe /FileNamePath:C:\Windows\System32\config\SAM
RawCopy.exe /FileNamePath:C:\Windows\System32\config\Security
RawCopy.exe /FileNamePath:C:\Windows\System32\config\Software
RawCopy.exe /FileNamePath:C:\Windows\System32\config\System
RawCopy.exe /FileNamePath:C:\Windows\System32\config\Default
RawCopy.exe /FileNamePath:C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\UsrClass.dat
RawCopy.exe /FileNamePath:C:\Users\%USERNAME%\NTUSER.dat
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
	
REM echo #------------------------------------- Amcache Files copied to IR-Collection folder -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
REM robocopy /b C:\Windows\appcompat\Programs\  .\IR-Collection\Prefetch Amcache.hve
REM echo. >>Win-IR-Output-%COMPUTERNAME%.txt




echo #------------------------------------- System Related Information ------------------------------------- #>>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############  System information  ############>>Win-IR-Output-%COMPUTERNAME%.txt
systeminfo  >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############  Hostname of system  ############ >>Win-IR-Output-%COMPUTERNAME%.txt
hostname >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Current User  ############ >>Win-IR-Output-%COMPUTERNAME%.txt
whoami  /all>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Users of Current system ############ >>Win-IR-Output-%COMPUTERNAME%.txt
net users >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ Dir listing of users directory in windows folder############ >>Win-IR-Output-%COMPUTERNAME%.txt
dir /Q c:\users>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Sessions open on current system ############ >>Win-IR-Output-%COMPUTERNAME%.txt
net session /list >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Available shares on the system ############ >>Win-IR-Output-%COMPUTERNAME%.txt
net share >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt


echo #------------------------------------- Network Related information -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ IP address and adapter details ############ >>Win-IR-Output-%COMPUTERNAME%.txt
ipconfig /all >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ System routing entries ############ >>Win-IR-Output-%COMPUTERNAME%.txt
route print >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ ARP cache entries ############ >>Win-IR-Output-%COMPUTERNAME%.txt
arp -a >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Network connections ############ >>Win-IR-Output-%COMPUTERNAME%.txt
netstat -ano >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Firewall Status and Config -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ Firewall Status ############ >>Win-IR-Output-%COMPUTERNAME%.txt
netsh firewall show state >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Firewall Configuration ############ >>Win-IR-Output-%COMPUTERNAME%.txt
netsh firewall show config >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Running processes and services -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ List all services ############ >>Win-IR-Output-%COMPUTERNAME%.txt
sc queryex type= service state= all >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Started Windows Services ############ >>Win-IR-Output-%COMPUTERNAME%.txt
net start>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Running Processes and started services  ############ >>Win-IR-Output-%COMPUTERNAME%.txt
tasklist /SVC>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Installed Patches and Hotfixes -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
wmic qfe get Caption,Description,HotFixID,InstalledOn >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Installed Programs-------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
powershell get-wmiobject -Class win32_product >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt


echo #------------------------------------- Mapped Drive and Shares-------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ Resources being accessed on the Network ############ >>Win-IR-Output-%COMPUTERNAME%.txt
net use >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Drives mounted on the system and space ############ >>Win-IR-Output-%COMPUTERNAME%.txt
powershell Get-WmiObject -Class Win32_LogicalDisk >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Scheduled Taks -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
schtasks /query /fo LIST /v >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------ USB devices connected to system uptil now -------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt
powershell Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | findstr FriendlyName>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt


echo #------------------------------------- File listing of common user directories -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt

echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ User creation date found in  C:\Users ##################>>Win-IR-Output-%COMPUTERNAME%.txt
dir /T /C "C:\Users"  >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Files Inside  C:\Users\%USERNAME%\Downloads\ ##################>>Win-IR-Output-%COMPUTERNAME%.txt
dir /q /R "C:\Users\%USERNAME%\Downloads\"  >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Files Inside  C:\Windows\temp\ ##################>>Win-IR-Output-%COMPUTERNAME%.txt
dir /q /R C:\Windows\temp\  >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Files Inside  C:\Temp\ ##################>>Win-IR-Output-%COMPUTERNAME%.txt
dir /q /R C:\Temp\  >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Files Inside  C:\Users\%USERNAME%\AppData\Local\Temp\  ##################>>Win-IR-Output-%COMPUTERNAME%.txt
dir /q /R "C:\Users\%USERNAME%\AppData\Local\Temp\"  >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo ############ Files Inside  C:\Windows\SoftwareDistribution\Download ##################>>Win-IR-Output-%COMPUTERNAME%.txt
dir /q /R C:\Windows\SoftwareDistribution\Download >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt



echo ############ AD policies deployed##################>>Win-IR-Output-%COMPUTERNAME%.txt
powershell Get-GPO -All>>Win-IR-Output-%COMPUTERNAME%.txt
echo ########################################
gpresult /Scope Computer /v >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

echo #------------------------------------- Interesting artifacts in Registry-------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ Entries in common startup location for persistance  ##################>>Win-IR-Output-%COMPUTERNAME%.txt
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run. >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run. >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce. >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce. >>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

REM  ####New additions in version 2 of this script.
echo ############ Configured Time Zone ##################>>Win-IR-Output-%COMPUTERNAME%.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\ |findstr TimeZoneKeyName>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt
echo ############ Configured DHCP Server ##################>>Win-IR-Output-%COMPUTERNAME%.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\|findstr DhcpNameServer>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

REM #####April 2021 additions 
REM reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords
HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords
HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords
HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords

REM  https://support.microsoft.com/en-us/help/314053/tcp-ip-and-nbt-configuration-parameters-for-windows-xp
REM reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\(interFace id)\EnableDhcp

echo #------------------------------------- Hash of all running processes ------------------------------------->>Win-IR-Output-%COMPUTERNAME%.txt
powershell -nop -exec bypass -File processhash.ps1>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt

 echo #------------------------------------- Potentially Interesting Files -------------------------------------# >>Win-IR-Output-%COMPUTERNAME%.txt
 echo. >>Win-IR-Output-%COMPUTERNAME%.txt
powershell get-childitem "C:\Users\." -recurse -Include *.exe, *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.xml,*.ini,*.vbs,*.bat,*.ps1,*.msi,*.cmd -EA SilentlyContinue >>Win-IR-Output-%COMPUTERNAME%.txt
 echo. >>Win-IR-Output-%COMPUTERNAME%.txt
 
 
 echo #------------------------------------- Microsoft Office macro execution evidence  ------------------------------------->>Win-IR-Output-%COMPUTERNAME%.txt
powershell -nop -exec bypass -File officeMacroExecution.ps1>>Win-IR-Output-%COMPUTERNAME%.txt
echo. >>Win-IR-Output-%COMPUTERNAME%.txt




echo ##########--------###########  End of Script  #############------##############
echo All  outputs from this script would be saved in the current working directory. Kindly share the folder - [Windows-IR-Script-v2] with IR team.

REM ### Contact me if any issue faced- litemployee1@gmail.com ###
