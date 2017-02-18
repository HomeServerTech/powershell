function Create-Task{
<#
    .Synopsis
       Creates a Scheduled Task
    .DESCRIPTION
       Executes a powershell script to be run as a scheduled task.
    .EXAMPLE
       Example of how to use this cmdlet
    .EXAMPLE
       Another example of how to use this cmdlet
    .LINK
        https://technet.microsoft.com/en-us/library/jj649816%28v=wps.630%29.aspx
#>
[CmdletBinding()]
    param(
    # The name of the task as it appears in task scheduler.
    [parameter(Mandatory=$true)][alias("t","TN")][string]$TaskName,

    # The description of the task as it appears in task scheduler.
    [parameter(Mandatory=$true)] [alias("d")][string]$Description,

    # Powershell code to be executed when the script is run.
    [parameter(Mandatory=$true)][alias("script","code","s")][string]$scriptblock,

    # Total allowable execution time of the task.
    [parameter(Mandatory=$false)][alias("e")][INT]$ExecutionTimeLimit=5,

    # Random delay after startup.
    [parameter(Mandatory=$false)][alias("r")][INT]$RandomDelay=1

    )
    begin{
    write-log "Createing scheduled task. $TaskName - $Description"
    }
    process{
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command ${scriptblock}"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Days $ExecutionTimeLimit)
    $trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes $RandomDelay)
    $task = Register-ScheduledTask -Force -TaskName $TaskName -Description $Description -TaskPath \devops\ -Action $action -Trigger $trigger -Settings $settings -User SYSTEM
    $task | Start-ScheduledTask
    }
    end{
    write-log "$TaskName created successfully."
    }
}# END Function Create-Task
