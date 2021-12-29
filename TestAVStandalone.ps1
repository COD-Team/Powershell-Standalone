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
        
    .FUNCTIONALITY
        PowerShell Language
    
    .NOTES
    
    .LINK
        https://github.com/COD-Team/

#>

#Requires -RunAsAdministrator

$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

$Tasks = @(
    ,"CreateEICAR"
    #,"DownloadEICAR.COM"
    #,"DownloadEICAR.ZIP"
    #,"DownloadEICAR2.ZIP"
    )

# Set your Log Path, can be local or a Network Share - Results CAN be different suggest running both
$logpath = "C:\COD-Logs\$env:ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }

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