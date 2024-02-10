# IR-Forensic-collection
Basic forensic artefact collection scripts

Disable any antivirus/EDR solution before running this script or put this folder under exception
You will have to run command prompt with admin privilege and navigate to the location where this script is downloaded and extracted. (Eg in CMD type > cd C:\Users\admin\Downloads\Windows-IR-Script-v2)
And then simply run the "Windows-IR-Script-v2.bat" from the cmd prompt.
This script will copy and generate many files/logs in its current working location.

Note :
	Below windows programs will be executed as part of this script:
 
	systeminfo
	hostname
	whoami
	net users
	ipconfig
	route
	arp
	netstat
	netsh
	sc
	net start
	tasklist
	wmic
	powershell
	net use
	schtasks
	findstr
	dir
	reg query
	robocopy
	RawCopy.exe
