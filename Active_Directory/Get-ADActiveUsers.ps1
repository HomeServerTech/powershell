$ADUsers = get-content $home\Desktop\users.txt
$info = @()

foreach ($ADUser in $ADUsers){
$Test=get-aduser -identity $ADUser 
        $AD_User_info = New-Object PSObject -Property @{
            Name = $Test.name
            Enabled = $Test.Enabled
            GivenName = $Test.GivenName
            SurName = $Test.SurName
            UserPrincipalName = $Test.UserPrincipalName
        }
        $info += $AD_User_info
}

$info | Export-Csv -UseCulture -NoTypeInformation $Home\Desktop\AD_User_info.csv
