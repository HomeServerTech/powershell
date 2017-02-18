

##################
#region Notes

# Set-content will overwrite existing file data
# Add-content will APPEND to existing file data.

# Use Where-Object {$_.Name -Like 'x*'} to filter out specific results with wildcard
# % = where-object alias

<#
To call a command stored in a variable use "&" before the variable
$variable = "C:\some\folder\install.exe

& $variable
#>

#endregion Notes
##################

##################
#region Code Snippets

# get-date formats: https://technet.microsoft.com/en-us/library/ee692801.aspx
# output date in this format - 2015-01-08 16:19:21
$TimeStamp = Get-Date -UFormat "%Y-%m-%d %H:%M:%S"

# Additional Date settings
(get-date).AddDays(-1)
[DateTime]::Today.AddDays(-1).AddHours(22)
[DateTime]::Today
[DateTime]::Now.AddHours(-10)

# From: https://blogs.technet.microsoft.com/heyscriptingguy/2014/06/18/powertip-add-days-hours-and-minutes-to-current-time/
$timespan = New-TimeSpan -Hours 5
(get-date) + $timespan

# Sleep for 30 seconds with a counter.
# http://blogs.technet.com/b/heyscriptingguy/archive/2014/05/09/powershell-looping-the-continue-statement.aspx
[array]$a = 1..30 ; foreach ($i in $a){write-host -nonewline "$i..";Sleep 1}

# Import module for specific PS commands. Example: AD, Exchange, SQL, etc.
#region Import Module for Active Directory
Try { 
  Import-Module ActiveDirectory -ErrorAction Stop 
} 
Catch { 
  Write-Host "[ERROR]`t ActiveDirectory Module couldn't be loaded. Script will stop!" 
  Exit 1 
}
#endregion Import Module for Active Directory

# Not Test-Path
if(!(Test-Path -Path $path)){
   new-item -Path $path -Value "new file" –itemtype file
  }
else{
   Add-Content -Path $path -Value "`r`n Additional content"
  }


################################################################
### HOW to use Invoke-command to run AD queries in parellel. ###
################################################################
#Save this script as a separate script from the one in filepath below.

#Here’s a way to get all servers right out of AD. 
# Note that it grabs JWTCVP servers and only the first 40.
# Nice to limit results when your just testing
$srvs = get-adcomputer -f {name -like "SERVERNAME*"} | Select -exp Name | Select -First 40

#This will invoke the command in –FilePath below simultaneously on all the servers. 
# Runs about ten times faster than a foreach loop.

Invoke-Command -ComputerName $srvs -FilePath {~\scripts\get-Info.ps1} -ea 0
################################################################

###################################
### HOW to output to a csv file ###
###################################
$TimeStamp = Get-Date -UFormat "%Y-%m-%d %H:%M:%S"

$OutFile = "dns_settings_$TimeStamp.csv"
if(!(Test-Path $OutFile)){
    New-Item -ItemType File "$OutFile"
}
# Rename the old log file, if it exists
if(Test-Path $OutFile) {
	$DateString = Get-Date((Get-Item $OutFile).LastWriteTIme) -format MMddyyyy
	Move-Item $OutFile "$OutFile.$DateString.csv" -Force -Confirm:$false
}

# CSV headers for the log file
Add-Content $OutFile "Date,Server,DNSOrder,Result"

# add entry for data
Add-Content $OutFile ($TimeStamp+","+$network.PSComputerName+","+$network.DNSServerSearchOrder+",Ok")
Add-Content $OutFile ($TimeStamp+","+$VMHost.Parent+","+$VMHost.Name+",Success")
###################################

# Pin Item to taskbar
$sa = new-object -c shell.application;$pn = $sa.namespace($env:windir).parsename('powershell.exe')
$pn.invokeverb('taskbarpin')
# to unpin item
$pn.invokeverb('taskbarunpin')

###################################
# Output credentials to an encrypted file
$credential = Get-Credential
$credential.Password | ConvertFrom-SecureString | Set-Content c:\Users\e04252d\keys\cred1.txt

$UseCredential = get-content c:\Users\e04252d\keys\cred1.txt | ConvertTo-SecureString

# Basic emailing from SMTP client
$EmailFrom = "myemail@gmail.com"
$EmailTo = "myemail+alerts@gmail.com"
$Subject = "I did some stuff!"
$Body = "This is a notification from Powershell."
$SMTPServer = "smtp.gmail.com"
$SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
$SMTPClient.EnableSsl = $true
$SMTPClient.Credentials = $credential;
$SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)

# basic error handling
$ErrorLog = "E:\PowerShell\Change_Admin_Password\ErrorLog.txt"
$error.clear()
try { something }
catch { 
"ERROR on $computer : $_" | Add-Content $ErrorLog 
}

# Search for mounted Hard drives
$disks = gwmi win32_logicaldisk -Filter "DriveType='3'" | select -ExpandProperty DeviceID

# Select all devices that do not have deviceids a,b,c,k or l, followed by colon
$avail = $disks | ? { $_.DeviceID -notmatch "[abckl]:"}


# How to combine object properties for output to Export-CSV
# =========================================================
$PhysicalMemory = (get-wmiObject -class win32_ComputerSystem).TotalPhysicalMemory
$Bios = get-wmiObject -class win32_Bios
$LocalTime = get-wmiObject -class win32_LocalTime
$OperatingSystem = get-wmiObject -class win32_OperatingSystem
$Processor = get-wmiObject -class win32_Processor
$TimeAndDate = get-date

$o = new-object PSObject
$o | add-member NoteProperty PhysicalMemory $PhysicalMemory
$o | add-member NoteProperty Bios $Bios
$o | add-member NoteProperty LocalTime $LocalTime
$o | add-member NoteProperty OperatingSystem $OperatingSystem
$o | add-member NoteProperty Processor $Processor
$o | add-member NoteProperty TimeAndDate $TimeAndDate

$o | export-csv "outputfile.csv" -notypeinformation
# =========================================================

# Progress Counter 1
for ($i = 1; $i -le 100; $i++ )
    {write-progress -activity "Scanning Servers" -status "$i% Complete:" -percentcomplete $i;}
# Progress Counter 2 for subroutine in function.
for($j = 1; $j -lt 101; $j++ )
    {write-progress -id  1 -activity Updating -status 'Progress' -percentcomplete $j -currentOperation InnerLoop} }
 
#Progress meter
$MeasureServers = @($servers).count
    $i++ #Add iteration
    $intSize = $intSize + $MeasureServers #Add +1 to server progress
    # Write progress as percentage of all servers completed.
    Write-Progress -activity "Finding DNS settings" -status "Servers Queried: $i / $MeasureServers" -PercentComplete (($i/$MeasureServers)  * 100)           

# Progress spinner
while ($true) {
    Write-Host "`r|" -NoNewline; sleep 1
    Write-Host "`r/" -NoNewline; sleep 1
    Write-Host "`r-" -NoNewline; sleep 1
    Write-Host "`r\" -NoNewline; sleep 1
}

# Progress dots using .NET
while ($true) {
    [Console]::Write(".")
    for ($i = 1; $i -lt 60; $i++)
    {[Console]::Write("."); sleep 1}
}
[Console]::Write("done.")

# Sleep timer for 30 seconds with write-host progress
[array]$a = 1..30 ; foreach ($i in $a){write-host -nonewline "$i.";Sleep 1}

#Event Viewer codes
get-eventlog -LogName System -EntryType Error -After 2016-01-30 -Before 2016-01-31

# Count items - useful in progress meters.
#This just returns the Count property of the array returned by the antecedent sub-expression:

    @(Get-Alias).Count

# A couple points to note:
# 1)You can put an arbitrarily complex expression in place of Get-Alias, for example:

    @(Get-Process | ? { $_.ProcessName -eq "svchost" }).Count

# 2) The initial at-sign (@) is necessary for a robust solution. As long as the answer is 
#two or greater you will get an equivalent answer with or without the @, but when the 
#answer is zero or one you will get no output unless you have the @ sign! 
#(It forces the Count property to exist by forcing the output to be an array.)


# parrallel WMI calls.
$scriptblock = {
    Param($server)
    IF (Test-Connection $server -Quiet){
        $wmi = (gwmi win32_computersystem -ComputerName $server).Name
        Write-Host "***$server responds: WMI reports the name is: $wmi"
    } ELSE { Write-Host "***$server ERROR -Not responding***" }
}
$servers | % {Start-Job -Scriptblock $scriptblock -ArgumentList $_ | Out-Null}
Get-Job | Wait-Job | Receive-Job


#Counstruct an Array, and add each loop iteration, THEN output to CSV, 
# so you Don't have to APPEND each time!!! DUH!!!
# =========================================================
#Construct an out-array to use for data export
$OutArray = @()
#The computer loop you already have
foreach ($server in $serverlist)
    {
        #Construct an object
        $myobj = "" | Select "computer","Speed","Regcheck"
        #fill the object
        $myobj.computer = $computer
        $myobj.speed = $speed
        $myobj.regcheck = $regcheck

        #Add the object to the out-array
        $outarray += $myobj

        #Wipe the object just to be sure
        $myobj = $null
    }
#After the loop, export the array to CSV
$outarray | export-csv "somefile.csv"
# =========================================================


# Find SQL Server Instances 
$SQLServices = gwmi -query "select * from win32_service where Name LIKE 'MSSQL%' and Description LIKE '%transaction%'"

forEach ($SQLService in $SQLServices) {
write-host $SQLService.Name $SQLService.State
} 

#endregion Code snippets
##################

##################
#region debug code comments

# This will display comments when using the "-Debug" parameter
# PS 4.0+ only
Write-Debug ($VMHost.Name + " - password changed")

#endregion debug code comments
##################

##################
#region One Liners
<#
###############################################################
FILENAME :  one_liners.ps1

AUTHOR   :  Randy Coran
EMAIL    :  Randy.Coran@gmail.com

DATE     :  2014-10-03
EDIT     :  2014-11-11 (A)

COMMENT  :  Default comment goes here.

VERSION   : 0.X
CHANGELOG :
    0.X - One Liners
###############################################################
#>

##################
#region General 

#Powershell version
$PSVersionTable.PSVersion

# windows OS version
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724833%28v=vs.85%29.aspx
# [Source]https://stackoverflow.com/questions/7330187/how-to-find-the-windows-version-from-the-powershell-command-line
[System.Environment]::OSVersion.Version

# Stop Server Manager from running at logon. (Finally!)
Disable-ScheduledTask -TaskPath ‘\Microsoft\Windows\Server Manager\’ -TaskName ‘ServerManager’

# System uptime
($(get-date) - (Get-CimInstance -ClassName win32_operatingsystem).lastbootuptime) | ft

# Tailing Log files
# From: https://devbeard.com/log-tail-with-powershell/
Get-Content mylogfile.log -Wait -Tail 10

# Measure time for a command to finish.
measure-command {get-process} | select @{n="time";e={$_.Minutes,"Minutes",$_.Seconds,"Seconds",$_.Milliseconds,"Milliseconds" -join " "}}

# Enable "show extensions for know file types", uncomment "ShowSuperHidden" for seeing protected windows files.
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
Set-ItemProperty $key HideFileExt 0
#Set-ItemProperty $key ShowSuperHidden 1
Stop-Process -processname explorer

# determine disk cluster size, 4096 or 16k or 64k for SQL server virtual disks.
gwmi -Query $("SELECT Label,Blocksize,Name FROM Win32_Volume WHERE FileSystem='NTFS'") -CN '.' | Select Label,Blocksize,Name

gwmi -Query $("FROM Win32_Volume WHERE FileSystem='NTFS'")

# List installed Server features
Get-WindowsFeature | ? {$_.Installed -match “True”} | Select -exp Name

# List running services
Get-service | ? {$_.Status -match “Running”} | Select -exp Name

Get-service | ? {$_.Status -match “Running”} | ? {$_.Name -match “Winmgmt”}

# Install telnet from PS
install-windowsfeature "telnet-client" 

# NTP query for WIndows
w32tm /query /configuration
w32tm /query /status
Time /T 

# Run a script from a URL
Invoke-Expression((Invoke-WebRequest http://pastebin.com/raw.php?i=sWacjDpa).content)

# open network settings by searching in start menu
ncpa.cpl

# Show network interface priority and routing table.
netstat -rn

# Stop a process that has been running for more than one day.
Get-Process powershell | ? { ([DateTime]::Now - $_.StartTime).TotalSeconds -gt 86300 } | Stop-Process -force

# Have the computer default voice speak
(New-Object Com SAPI.SPVoice).Speak("The time is $(get-date -format t).")

# Manually add info to a CSV output file
Add-Content $Logfile ((get-date -Format "dd/MM/yy HH:mm")+","+$VMHost.Parent+","+$VMHost.Name+",Success")

# Find IP information from remote server via WMI call
gwmi -Class Win32_NetworkAdapterConfiguration -ComputerName $(hostname) -filter IpEnabled="True" | select __SERVER,IPAddress,DNSServerSearchOrder | ft -autosize

# Test a local ps session for windows remoting
Enter-PSSession -ComputerName localhost

# Ping subnet IP range
for($i=1;$i-lt255;$i++){ping 192.168.1.$i -n 1 -w 100}
for($i=1;$i-lt255;$i++){Test-Connection -Quiet -Count 2 192.168.1.$i ; if($?){write-output "192.168.1.$i Active"}

# Alphabet array
$alph=@();65..90|foreach-object{$alph+=[char]$_};$alph

# Create local user
(([adsi]"WinNT://.").Create("User","MyTestUser")).SetInfo()
# Create local group
(([adsi]"WinNT://.").Create("Group","MyTestGroup")).SetInfo()

# Cat outfile, then remove the empty lines, the rewrite file without empty lines.
(gc $OutFile) | ? {$_.trim() -ne "" } | set-content $OutFile

#  FileServer 4 testing output
$OF="~\out_$(get-date -uformat "%Y%m%d-%H%M").txt";

for($i=1;$i-lt10;$i++){ps|sort -des cpu|select -f 30|ft -a >>C:\FS4M\out_$(get-date -uformat "%Y%m%d-%H%M").txt;sleep 2}
ping xwtcvpua >>C:\FS4M\out_$(get-date -uformat "%Y%m%d-%H%M").txt;ping Xwtcvpdb09a >>C:\FS4M\out_$(get-date -uformat "%Y%m%d-%H%M").txt;ping Xwtcvpapp02b >>C:\FS4M\out_$(get-date -uformat "%Y%m%d-%H%M").txt
get-service|where{$_.Status-eq'Running'}>>C:\FS4M\out_$(get-date -uformat "%Y%m%d-%H%M").txt

# Testing of ping and memory usage

(test-connection "Server1", "Server2", "Server3")
get-date -uformat"%Y%m%d-%H%M"

for ($i=1;$i-lt10;$i++){ps|sort -des cpu|select -f 30|ft -a;sleep 2};
ping Server1;ping Server2;ping Server3

# Show pagefile usage
Get-WmiObject -Class Win32_PageFileUsage | Select AllocatedBaseSize,Description,Status,Name,Peakusage,TempPageFile | FL

#endregion GENERAL
##################

##################
#region Active Directory

# Add a computer to AD
Add-Computer -PassThru -DomainName contoso.com -credential $cred -oupath "OU=RSCloud,OU=Rackspace,OU=Servers,OU=Computers,OU=contoso,DC=contoso,DC=local"


# Test if computer is in AD and a specific domain.
$ComputerSystem = gwmi win32_computersystem
(($ComputerSystem.domain -like 'contoso*') -and $ComputerSystem.partofdomain)
(gwmi win32_computersystem).domain
(gwmi win32_computersystem).partofdomain
gwmi win32_computersystem | select domain,partofdomain

# Export all AD object properties to CSV file
csvde -f test.csv

# Get group membership of an AD user
Get-ADPrincipalGroupMembership username | select name

# AD Computer name queries
Get-ADComputer -Filter {Name -Like "ServerName*"} | Select -exp Name | Sort-Object
Get-ADComputer -Filter {(OperatingSystem -Like "Windows Server*") -and (Name -notLike "ServerName*")} -Properties Name,OperatingSystem | Select Name,OperatingSystem | Sort-Object 
Get-ADComputer -Filter {(OperatingSystem -Like "Windows Server*") -and (Name -Like "ServerName1*") -and (Name -notLike "ServerName2*") -and (Name -notLike "ServerName3*")} -Properties Name,OperatingSystem | Select Name,OperatingSystem | Sort-Object 

# AD user search
get-aduser -Filter {Name -Like "*UserNameHere*"}

# Query AD for computer names
Get-ADComputer -Filter {Name -Like "ServerName*"} | Select -exp Name | Sort
Get-ADComputer -filter {(Name -NotLike "ServerName*") -AND (OperatingSystem -Like "Windows Server*")} | Select -exp Name | sort

# Show DC that has FSMO roles
Get-ADForest bdm.dom | FT SchemaMaster,DomainNamingMaster
Get-ADDomain bdm.dom | FT PDCEmulator,RIDMaster,InfrastructureMaster 
# CMD command
netdom query fsmo

# Find DC that provided information to computer.
gpresult /r /scope:computer

# Force a specific DC to be used
nltest /Server:myfileserver /SC_RESET:DOMAIN\DCServerName

#endregion Active Directory
##################

##################
#region SQL

# Get current SQL version.
Invoke-Sqlcmd -Query "SELECT @@VERSION;" -QueryTimeout 3

#endregion SQL
##################

##################
#region DNS

# Commands for changing DNS settings remotely:
# Windows 2k8r2 / Windows 7 and earlier.
$NetworkAdapterConfig = Get-WMIObject -Class Win32_NetworkAdapterConfiguration | ? {$_.IPEnabled} | select DNSServerSearchOrder
$NetworkAdapterConfig.DNSServerSearchOrder = “10.0.0.1”,”10.0.0.2”
# windows 2k12 and windows 8 and newer.
Set-DNSClientServerAddress –interfaceIndex 12 –ServerAddresses (“10.0.0.1”,”10.0.0.2”)

# Change DNS search order
(gwmi Win32_NetworkAdapterConfiguration -filter "IPEnabled=True").DNSServerSearchOrder

# This works best for setting DNS.
$DnsServerArray='172.20.112.91','10.0.0.22','192.168.42.11';$Network=gwmi Win32_NetworkAdapterConfiguration -filter "IPEnabled=True";$Network.SetDNSServerSearchOrder($DnsServerArray)

#endregion DNS
##################

#region Windows Updates

# Disk cleanup replacement for Server 2012r2
dism.exe /online /cleanup-image /spsuperseded

#endregion Windows Updates


##################
#region Files and Drives

# Disk drive letters from WMI
gwmi win32_logicaldisk -cn $s -Filter "DriveType='3'" | select -ExpandProperty DeviceID

# Change drive letters.
swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'E:'") -Arguments @{DriveLetter="P:"}
swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'D:'") -Arguments @{DriveLetter="E:"}
swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'P:'") -Arguments @{DriveLetter="D:"} 

#Pastable form of above
swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'E:'") -Arguments @{DriveLetter="P:"}; swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'D:'") -Arguments @{DriveLetter="E:"}; swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'P:'") -Arguments @{DriveLetter="D:"} 

swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'E:'") -Arguments @{DriveLetter="F:"};
swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'D:'") -Arguments @{DriveLetter="F:"};
swmi -input (gwmi -Class win32_volume -Filter "DriveLetter = 'F:'") -Arguments @{DriveLetter="D:"}

# Initialize and format a RAW disk, for when you add a new disk to a VM.
Import-Module Storage ; 
Get-Disk | 
Where partitionstyle -eq 'raw' | 
Initialize-Disk -PartitionStyle GPT -PassThru | 
New-Partition -AssignDriveLetter -UseMaximumSize |
Format-Volume -FileSystem NTFS -NewFileSystemLabel "Application" -Confirm:$false

# For SQL servers, to initialize disk.
Import-Module Storage ; 
Get-Disk | 
Where partitionstyle -eq 'raw' | 
Initialize-Disk -PartitionStyle MBR -PassThru | 
New-Partition -AssignDriveLetter -UseMaximumSize |
Format-Volume -FileSystem NTFS -NewFileSystemLabel "Application" -AllocationUnitSize 64K -Confirm:$false



#endregion Files and Drives
##################

##################
#region Exchange

# Exchange, Get info for Which DB is active copy and mounted.
get-MailboxDatabaseCopyStatus -Identity DB5 | select Name,Status,ActiveCopy,CopyQueueLength,ReplayQueueLength | sort name | ft
get-MailboxDatabaseCopyStatus -Server MailServer | select Name,Status,ActiveCopy,CopyQueueLength,ReplayQueueLength | sort name | ft
get-MailboxDatabaseCopyStatus -identity DB2\MailServer | select Name,Status,ActiveCopy,CopyQueueLength,ReplayQueueLength | sort name | ft

# Show Exchanged database size in GB
get-mailboxdatabase | foreach-object{select-object -inputobject $_ -property *,@{name="MailboxDBSizeinGB";expression={[math]::Round(((get-item ("\\" + $_.servername + "\" + $_.edbfilepath.pathname.replace(":","$"))).length / 1GB),2)}}} | Sort-Object mailboxdbsizeinGB -Descending | format-table identity,mailboxdbsizeinGB -autosize

# Add Database to mailserver
Add-MailboxDatabaseCopy -Identity 'db20'-MailboxServer 'MailServer' -ActivationPreference '5'

#Message tracking by time via Powershell EMC(Exchange Managment Console.)
Get-MessageTrackingLog –Sender “Name@domain.com” –Recipients “Randy.Coran@domain.com” -Start "7/30/2015 10:40AM" -End "7/30/2015 11:30AM" 

# GET eXCHANGE aTTACHMENT SIZE SETTINGS
get-transportconfig | ft maxsendsize, maxreceivesize 
get-receiveconnector | ft name, maxmessagesize 
get-sendconnector | ft name, maxmessagesize 
get-mailbox Administrator |ft Name, Maxsendsize, maxreceivesize

#endregion Exchange
##################

##################
#region PowerCLI

# Export the virtual Port Group from a cluster in ESX
$cluster = "VMClusterName" ; get-cluster $cluster | Get-VMHost | Get-VirtualPortGroup | select VirtualSwitch,Name | Export-csv -path "~\Desktop\VMPortGroup_$cluster.csv" -NoTypeInformation

# PowerCLI export virtual port groups to csv
Get-VirtualSwitch -Distributed | select * | sort name | %{Get-VirtualPortGroup -VirtualSwitch $_.name} | export-csv E:\PowerShell\PowerCLI\vds_info.csv -notypeinformation

# Find VMs with storage in different datastores.
get-datastore -name Cluster_?_* | %{get-vm -location ClusterName -datastore $_ -name ServerName*} | select name

# Distributed switch one liners
Get-VirtualSwitch -name Cluster_LAN_dvSwitch -Distributed | select * | sort name | %{Get-VirtualPortGroup -VirtualSwitch $_.name} | export-csv E:\vds_info.csv -notypeinformation
Get-VirtualSwitch -Distributed | sort name | %{Get-VirtualPortGroup -VirtualSwitch $_.name | select *} | export-csv vds_info2.csv -notypeinformation
Get-VirtualPortGroup -Distributed | sort name
Get-VirtualSwitch -name Cluster_LAN_dvSwitch -Distributed | select * | sort name | %{Get-VirtualPortGroup -VirtualSwitch $_.name} | export-csv E:\vds_info.csv -notypeinformation
Get-VirtualPortGroup -VirtualSwitch Cluster_LAN_dvSwitch | select Name, VirtualSwitch, VLanId
Get-VirtualPortGroup -VMHost VMHostName.corp.dom | select Name, VirtualSwitch, VLanId
Get-VirtualSwitch -name ClusterName -Distributed | sort name | Get-VirtualPortGroup -VirtualSwitch $_.name

#endregion PowerCLI
##################

##################
#region Networking

# List all listening ports of the server, 
# similar to netstat command, but it returns an oject instead of a string.
Get-NetTCPConnection -State Listen | ft state,l*port, l*address, r*port, r*address Auto

# Continuous ping for exporting to log file.
ping -t 172.20.112.89 | %{$a=Get-Date -UFormat "%Y-%m-%d %H:%M:%S"; write "$a $_"}

# Three different ways to map a network drive.
write "Map Z: drive"
$User = "domain\username"
$password = "P@ssword!"
$PWord = ConvertTo-SecureString -String "P@ssword!" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$FileServer = "\\servername\folder"
$ServerName = "rs-sql-db5.contoso.com"

# Using New-PSDrive, does not work after reboot.
New-PSDrive -Name I -PSProvider FileSystem -Root $FileServer -Credential $Credential -Persist

# Using VBScript
$net = new-object -ComObject WScript.Network
$net.MapNetworkDrive("z:",$User,$true, $FileServer, $password)

# using old skool cmmand line commands.
cmdkey /add:$ServerName /User:$user /Pass:$passwd
net use I: $FileServer /persistent:yes /savecred

#endregion Networking
##################

##################
#region Event logs

#Parse Windows event logs from specific tdays and times
# https://technet.microsoft.com/en-us/library/Hh849834.aspx
get-eventlog -LogName System -EntryType Error -After ([DateTime]::Now.AddDays(-4).AddHours(-14)) -Before ([DateTime]::Now.AddDays(-3).AddHours(-1))

#endregion Event logs
##################

#endregion ONE LINERS
##################

##################
#region Data Handeling

#Data Handeling
#JSON
# This explains it well: http://powershelldistrict.com/powershell-json/
$FirstBootJSON = ConvertFrom-Json (get-content c:\\chef\\first-boot.json.tmp -Raw)

#Show a pop up window
# from: https://blogs.technet.microsoft.com/heyscriptingguy/2014/04/04/powertip-use-powershell-to-display-pop-up-window/
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup("Operation Completed",0,"Done",0x1)
# With a && statement
$wshell.Popup("Starting Task",0,"Done",0x1) ; if ($?){$wshell.Popup("Operation Completed",0,"Done",0x1)}

# Equivalant to && in powershell
# $? evaluates previous command, if there is no errors $? is true, if there is erros $? is false.
# More about Powershell automatic variables: https://technet.microsoft.com/en-us/library/hh847768.aspx
Do-this; if ($?) {do-that}

#endregion Data Handeling
##################

##################
#region Functions

# unzip files from the command Line.
# Function to unzip files
# Example Expand-ZIPFile –File “C:\howtogeeksite.zip” –Destination “C:\temp\howtogeek”
# Credit from here: http://www.howtogeek.com/tips/how-to-extract-zip-files-using-powershell/
function Expand-ZIPFile($file, $destination)
{
$shell = new-object -com shell.application
$zip = $shell.NameSpace($file)
  foreach($item in $zip.items())
  {
  $shell.Namespace($destination).copyhere($item)
  }
}

# Overwrite existing files.
# Function to unzip files
# Example Expand-ZIPFile –File “C:\howtogeeksite.zip” –Destination “C:\temp\howtogeek”
# Credit from here: http://www.howtogeek.com/tips/how-to-extract-zip-files-using-powershell/
# http://stackoverflow.com/questions/2359372/how-do-i-overwrite-existing-items-with-folder-copyhere-in-powershell
# More reading: https://technet.microsoft.com/en-us/library/ee176633.aspx
<# 
.Synopsis
   unzip files
.DESCRIPTION
    Extract a single zip file to a folder.
.EXAMPLE
   Expand-ZIPFile –File “C:\file-To-Un.zip” –Destination “C:\temp\destinationfolder”
.INPUTS
    file, use '-file filename.zip' to specify zip file to extract.
.INPUTS
    destination, use '-destination foldername' to specify folder target.
.NOTES
    Found from here: http://www.howtogeek.com/tips/how-to-extract-zip-files-using-powershell/
#>
function Expand-ZIPFile($file, $destination){
$shell = new-object -com shell.application
$zip = $shell.NameSpace($file)
  foreach($item in $zip.items())
  {
  ($shell.Namespace($destination).copyhere($item), 0x14)
  }
}# END Function Expand-ZIPFile
Expand-ZIPFile -file C:\temp\cygwin64.zip -destination C:\temp\

# Unzip method function
# From: http://stackoverflow.com/questions/27768303/how-to-unzip-a-file-in-powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{param([string]$zipfile, [string]$outpath)
  [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

Unzip "C:\a.zip" "C:\a"

# Scheduled tasks cmdlets reference.: https://technet.microsoft.com/en-us/library/jj649816%28v=wps.630%29.aspx
#Sceduled taks
function Create-Task{
write "Registering Windows task for chef-client local run..."

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -noexit -ExecutionPolicy Bypass -Command "chef-client -z -c C:\dev\infrastructureautomation\scripts\client.rb -j c:\cloud-automation\first-boot.json --logfile C:\chef\chefrun.log"'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Days 7)
$trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 1)
$task = Register-ScheduledTask -Force -TaskName "taskname" -Description "Execute chef-client local run." -TaskPath \tasks\ -Action $action -Trigger $trigger -Settings $settings -User SYSTEM
$task | Start-ScheduledTask
}

# Slack webhook to post to a specific channel.
<# 
.Synopsis
   Post a message to Slack
.DESCRIPTION
    Using webhook to post to a specific slakc channel.
.EXAMPLE
   Post-ToSlack -channel '#devops' -botname ''
.INPUTS
    channel, use single quotes with a '#channelname' or '@username'
    botname, use single quotes, can be whatever you like.
    botemoji, use single quotes, can be whatever you like.
    message, use single quotes, variables should be able to be passed in with this message, like from the pipeline.
.NOTES
    Single quotes are a good idea, maybe.
    From: https://gist.github.com/magnetikonline/11007e42d86f490b84f8
    Also: 
#>
function Post-ToSlack {
    Param(
        
    [Parameter(Mandatory = $true,Position = 1,HelpMessage = 'Chat message')]
    [ValidateNotNullorEmpty()]
    [String]$Message,
    [Parameter(Mandatory = $false,Position = 0,HelpMessage = 'Slack channel')]
    [ValidateNotNullorEmpty()]
    [String]$Channel = "#powershell_api_test",
    [Parameter(Mandatory = $false,Position = 3,HelpMessage = 'Optional name for the bot')]
    [String]$BotName = "Secret Squirrel bot",
    [Parameter(Mandatory = $false,Position = 3,HelpMessage = 'Optional emoji for the bot')]
    [String]$BotEmoji = ":squirrel:"
    )

Set-StrictMode -Version Latest

#Slack webhook URL.
$uri = "https://hooks.slack.com/services/webhookSLUG"

$payload = @{
	"channel" = "$Channel";
	"icon_emoji" = "$BotEmoji";
	"text" = "$Message";
	"username" = "$BotName";
}

Invoke-WebRequest `
	-Uri $uri `
	-Method "POST" `
	-Body (ConvertTo-Json -Compress -InputObject $payload)

}

# Start-Progress
# Shows dots a a command runs in the background and is then output is assigned to a variable.
# http://powershell.com/cs/blogs/tips/archive/2012/04/20/adding-progress-to-long-running-cmdlets.aspx
function Start-Progress {
  param(
    [ScriptBlock]
    $code
  )
  
  $newPowerShell = [PowerShell]::Create().AddScript($code)
  $handle = $newPowerShell.BeginInvoke()
  
  while ($handle.IsCompleted -eq $false) {
    Write-Host '.' -NoNewline
    Start-Sleep -Milliseconds 500
  }
  
  Write-Host ''
  
  $newPowerShell.EndInvoke($handle)
  
  $newPowerShell.Runspace.Close()
  $newPowerShell.Dispose()
}


#endregion Functions
##################

##################
#region Git

# Print just the current branch.
#http://stackoverflow.com/questions/1417957/show-just-the-current-branch-in-git

git branch | awk '/\*/ { print $2; }'
git rev-parse --abbrev-ref HEAD

#endregion Git
##################


# This should be a function.
$ENV = '11390'
$DomainController = '172.20.112.91','10.0.0.22','192.168.42.11','192.168.42.16'
$TestServers = "cs-rs-db-$ENV","cs-rs-dn-$ENV"
foreach ($DC in $DomainController)
{
    foreach ($Computer in $TestServers)
    {
        echo "Scanning DC $DC for $computer computer object."
        $result = GET-ADCOMPUTER -SERVER $DC -F {NAME -LIKE $Computer} | Select -exp name
        if($result -ne $null){
        echo "$computer computer object exists in DC $DC"
        }
        else{
        echo "no object detected on $DC"
        }
    }
}




$password = convertto-securestring 'Password' -asplaintext -force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist "contoso\admin",$password

Add-Computer -DomainName contoso.com -passthru -verbose -Server ServerName.contoso.com -credential $cred -oupath "OU=RSCloud,OU=Rackspace,OU=Servers,OU=Computers,OU=contoso,DC=contoso,DC=local"
     

# temp.
measure-command {dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase} | select @{n="time";e={$_.Minutes,"Minutes",$_.Seconds,"Seconds",$_.Milliseconds,"Milliseconds" -join " "}}

$DnsServerArray='172.20.112.91','10.0.0.22','192.168.42.11';$Network=gwmi Win32_NetworkAdapterConfiguration | ? {($_.IPEnabled -eq "True") -and (!($_.ServiceName -like "VMnet*"))};$Network.SetDNSServerSearchOrder($DnsServerArray)

#powershell.exe -Command '
if (!(test-path C:\\chef\\purged_windows_updates.txt)) {
echo "Waiting for Chef run to finish...";sleep 10
}
else{
echo "chef run complete."
}


cd c:\buildarchive\rsautomation; git fetch origin; git reset --hard origin/master

restart-computer

### Monitor a specific file for log events.
# need to test output of chef run log for completion.

$Value1 = (cat c:\chef\chefrun.log -tail 5 | select-string -quiet "Chef Run complete")
$Value2 = (cat c:\chef\chefrun.log -tail 10 | select-string -quiet "Report handlers complete")

'powershell.exe -Command "cat c:\chef\chefrun.log -tail 5 | select-string -quiet \"Chef Run complete\"'

until ($done = $true){
if ($(cat c:\chef\chefrun.log -tail 5 | select-string -quiet "Chef Run complete")){
echo "Waiting for Chef run to finish..."
sleep 10
$done = $false
}
else {echo "chef run complete.";$done = $true}
}

do {sleep 10}until($(cat c:\chef\chefrun.log -tail 5 | sls -quiet "Chef Run complete") -eq $true)
do {sleep 10}until($(cat c:\chef\chefrun.log -tail 5 | select-string -quiet "Chef Run complete") -eq $true); echo "Chef Run complete"

if (!(test-path C:\\chef\\purged_windows_updates.txt)) {echo \"Waiting for Chef run to finish...\";sleep 10} else{echo \"chef run complete.\"}

do
{
    if (!$(cat c:\chef\chefrun.log -tail 5 | select-string -quiet "Chef Run complete")){
    echo "Waiting for Chef run to finish..."
    sleep 10
    $done = $false
    }
    else {
    echo "chef run complete."
    $done = $true
    }
}
until ($done -eq $true)
