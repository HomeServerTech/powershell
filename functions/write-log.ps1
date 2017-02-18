function write-log ($LogEntry) {
# Append date at the begining of a text entry to a file. in 2016-04-22T12:03:31 format
    echo $("$(Get-Date -Format s) $LogEntry").tostring() | tee $logfile -Append
}# END Function write-log
