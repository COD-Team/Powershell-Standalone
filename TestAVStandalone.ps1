<#
    .DESCRIPTION
        Use at your own risk, suggest reviewing the links below. Additionally verify
        the links and string from the offical link eicar.org.

        EICAR is a way to test your Anti-Virus programs without having to use a Real Virus, WHY? 
        Most malware disables AV and as an ADMIN you must test it is working as intented. 
        https://en.wikipedia.org/wiki/EICAR_test_file
        https://www.eicar.org/
        https://www.eicar.org/?page_id=3950
        This program can test multiple methods to verify your security suite is working as intented. 

        Recommend under Tasks, executing 1 at a time. 
 
    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\COMPUTERNAME\DATETIME
    
    .EXAMPLE
        1. PowerShell 5.1 Command Prompt (Admin) 
            "powershell -Executionpolicy Bypass -File PATH\FILENAME.ps1"
        2. Powershell 7.2.1 Command Prompt (Admin) 
            "pwsh -Executionpolicy Bypass -File PATH\FILENAME.ps1"

    .NOTES
        Author Perkins
        Last Update 1/7/22
        Updated 1/7/22 Tested and Validated PowerShell 5.1 and 7.2.1
    
        Powershell 5 or higher
        Run as Administrator
    
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
        https://github.com/COD-Team
        YouTube Video https://youtu.be/4LSMP0gj1IQ
#>

#Requires -RunAsAdministrator

$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

$Tasks = @(
    ,"CreateEICAR"
    #,"DownloadEICAR.COM"       # Requires Internet
    #,"DownloadEICAR.ZIP"       # Requires Internet
    #,"DownloadEICAR2.ZIP"      # Requires Internet
    )

# Set your Log Path, can be local or a Network Share - Results CAN be different suggest running both
$logpath = "C:\COD-Logs\$env:ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }

# Added 1/7/21 PowerShell 7.2.1 Compatibility for Out-File not printing escape characters
if ($PSVersionTable.PSVersion.major -ge 7) {$PSStyle.OutputRendering = 'PlainText'}

# Master.Log will be created in the logpath defined above, change the file name if you choose. Results only let you know it's been executed. 
$OutputFile = "$logpath\Master.log"
$counter = 0

Function CreateEICAR 
{
    Write-Output "EICAR Virus File Written, Check $logpath for EICAR.txt and check logs." | out-file -Append $OutputFile
    Write-Output "If $Logpath is a Network Share, Review Host Logs " | out-file -Append $OutputFile
    set-content "X5O!P%@AP[4`\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*" -path $logpath\EICAR.txt
    write-host -fore Red "Check $OutputFile for a file called EICAR.TXT, try to open"
}

Function DownloadEICAR.COM
{
    Write-Output "EICAR Virus File Downloaded, Check $logpath for EICAR.com and check logs." | out-file -Append $OutputFile
    Write-Output "If $Logpath is a Network Share, Review Host Logs " | out-file -Append $OutputFile
    Invoke-WebRequest -Uri 'https://secure.eicar.org/eicar.com' -OutFile $logpath\eicar.com
    write-host -fore Red "Check $OutputFile for a file called EICAR.COM, try to open"
}

Function DownloadEICAR.ZIP
{
    Write-Output "EICAR Virus File Downloaded, Check $logpath for EICAR.com and check logs." | out-file -Append $OutputFile
    Write-Output "If $Logpath is a Network Share, Review Host Logs " | out-file -Append $OutputFile
    Invoke-WebRequest -Uri 'https://secure.eicar.org/eicar_com.zip' -OutFile $logpath\eicar.com.zip
    write-host -fore Red "Check $OutputFile for a file called EICAR.COM.ZIP, try to open"
}

Function DownloadEICAR2.ZIP
{
    Write-Output "EICAR Virus File Downloaded, Check $logpath for EICAR.com and check logs." | out-file -Append $OutputFile
    Write-Output "If $Logpath is a Network Share, Review Host Logs " | out-file -Append $OutputFile
    Invoke-WebRequest -Uri 'https://secure.eicar.org/eicarcom2.zip' -OutFile $logpath\eicar.zip
    write-host -fore Red "Check $OutputFile for a file called EICAR.ZIP, try to open"
}

Foreach ($Task in $Tasks)
    {
        Write-Progress -Activity "Collecting Assessment Data" -Status "In progress: $Task" -PercentComplete (($Counter / $Tasks.count) * 100)
        " "
	    " "	
	    Write-Output "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        Write-Output " " | out-file -Append $OutputFile
        Write-Output "####################################### Running Function $Task #######################################" | out-file -Append $OutputFile	    
        Write-Output "------------------------------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
	    " "
        &$Task
        $Counter ++    
    }

write-host -fore green "Results saved to: $OutputFile" 
write-host -fore Red "Did your Antivirus Display Notification of a Virus"
write-host -fore green "Script Completed"
