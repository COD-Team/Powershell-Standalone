<#
    .DESCRIPTION
        Script returns local account information. 
        Useful when managing local accounts
        Joins Users and Focus on Local Admin Accounts

    .FUNCTIONALITY
        PowerShell Language
    
    .NOTES
    
    .LINK
        https://github.com/COD-Team/Powershell-Standalone

#>
#Requires -RunAsAdministrator

$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }


Get-LocalUser | 
    ForEach-Object { 
        $user = $_
        $PasswordLastSet = if ($null -ne $user.PasswordLastSet) {($user.PasswordLastSet).ToString('MM/dd/yyyy')} else {(get-date '01/01/2000').ToString('MM/dd/yyyy')}
        $PasswordAge = (new-timespan -start $(Get-date $PasswordLastSet) -end (get-date)).days
        $LastLogonDate = if ($null -ne $user.LastLogondate) {($user.LastLogondate).ToString('MM/dd/yyyy')} else {(get-date '01/01/2000').ToString('MM/dd/yyyy')}
        $LogonAge = (new-timespan -start $(Get-date $LastLogonDate) -end (get-date)).days

        return [PSCustomObject]@{ 
            "User"   = $user.Name
            "FullName"   = $user.FullName
            "enabled" = $user.enabled
            "lockedout" = $user.lockedout
            "PasswordLastSet" = $PasswordLastSet
            "PasswordAge" = $PasswordAge
            "LastLogonDate" = $LastLogonDate
            "LogonAge" = $LogonAge
            
            "Groups" = Get-LocalGroup -Name Administrators | Where-Object { 
                $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") 
            } | Select-Object -ExpandProperty "Name"
        } 
    } | 

    # Uncomment 1 of the items below pending what you are wishing to return
        
        # Return only Users who are Administrators for accounts that are enabled        
        #Where-Object Groups -eq Administrators | Where-Object enabled -eq $true | Format-Table
        #Where-Object Groups -eq Administrators | Where-Object enabled -eq $true | Export-Csv -Path c:\temp\localusers.csv

        #Returns only accounts that are enabled
        Where-Object enabled -eq $true | Format-Table
        #Where-Object enabled -eq $true | Export-Csv -Path c:\temp\localusers.csv

        #Returns ALL Local Accounts
        #Format-Table
        #Export-Csv -Path c:\temp\localusers.csv