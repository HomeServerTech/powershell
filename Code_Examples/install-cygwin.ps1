<#
# Author: Randy Coran
# License: MIT
#
# Script to auto install cygwin to a new windows installation with git, curl, and wget.
#
# Use "-NoADmin" argument if needed to install without admin permissions.
#>

param(
    [switch]$NoAdmin # Use "-NoADmin" argument if needed to install without admin permissions.
)

#region Functions
function Run-Main{
# Determine OS Architecture
$os=Get-WMIObject win32_operatingsystem
    if ($os.OSArchitecture -eq "64-bit"){
        Install-Cygwin64
    }
    elseif($os.OSArchitecture -eq "32-bit"){
        Install-Cygwin32
    }
} # END function Run-Main

Function Install-Cygwin64{

# folder check - cygwin64
$scriptsdir = "C:\cygwin64"
if (!(Test-Path -path $scriptsdir)) {mkdir $scriptsdir}

cd $scriptsdir

# Download Cygwin installer using System.Net.WebClient to avoid Internet explorer prerequisite.
# This allows downloading from Server Core
$url = "https://www.cygwin.com/setup-x86_64.exe"
$output = "C:\cygwin64\setup-x86_64.exe"
$start_time = Get-Date

(New-Object System.Net.WebClient).DownloadFile($url, $output)

Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)" 

# Execute install command, with or without Admin permissions.
    if($NoAdmin){
        C:\cygwin64\setup-x86_64.exe -q -B -R $scriptsdir -s http://cygwin.osuosl.org/ -P git,curl,wget
    }
    else{
        C:\cygwin64\setup-x86_64.exe -q -R $scriptsdir -s http://cygwin.osuosl.org/ -P git,curl,wget
    }

### Modify Powershell environment path ###
# Temporarily set environment path
$env:Path += ";C:\cygwin64\bin"

# Modify system environment variable
[Environment]::SetEnvironmentVariable( "Path", $env:Path, [System.EnvironmentVariableTarget]::Machine )

# Modify user environment variable
[Environment]::SetEnvironmentVariable( "INCLUDE", $env:INCLUDE, [System.EnvironmentVariableTarget]::User )

# Add to the system environment variable
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\cygwin64\bin", [EnvironmentVariableTarget]::Machine)

}# END Function Install-Cygwin64

Function Install-Cygwin32{

# folder check - cygwin32
$scriptsdir = "C:\cygwin32"
if (!(Test-Path -path $scriptsdir)) {mkdir $scriptsdir}

cd $scriptsdir

# Download Cygwin installer using System.Net.WebClient to avoid Internet explorer prerequisite.
# This allows downloading from Server Core
$url = "https://www.cygwin.com/setup-x86.exe"
$output = "C:\cygwin64\setup-x86.exe"
$start_time = Get-Date

(New-Object System.Net.WebClient).DownloadFile($url, $output)

Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)" 

    if($NoAdmin){
        C:\cygwin64\setup-x86.exe -q -B -R $scriptsdir -s http://cygwin.osuosl.org/ -P git,curl,wget
    }
    else{
        C:\cygwin64\setup-x86.exe -q -R $scriptsdir -s http://cygwin.osuosl.org/ -P git,curl,wget
    }

### Modify Powershell environment path ###
# Temporarily set environment path
$env:Path += ";C:\cygwin32\bin"

# Modify system environment variable
[Environment]::SetEnvironmentVariable( "Path", $env:Path, [System.EnvironmentVariableTarget]::Machine )

# Modify user environment variable
[Environment]::SetEnvironmentVariable( "INCLUDE", $env:INCLUDE, [System.EnvironmentVariableTarget]::User )

# Add to the system environment variable
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\cygwin32\bin", [EnvironmentVariableTarget]::Machine)

}# END Function Install-Cygwin32

#endregion Functions

# Execute main function
Run-Main
