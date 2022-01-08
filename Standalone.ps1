<#
    .DESCRIPTION
        Script pulls information from Local Workstation.

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
<#
$Tasks = @(
    ,""
    ,"LaunchNotepad"  
)
#>
$Tasks = @(
    ,"GetEvaluateSTIG"
    ,"GetWindowsVersion"
    ,"GetPowerShellVersion"
    ,"GetExecutionPolicy"
    ,"GetLocalUser"
    ,"GetLocalAdministrators"
    ,"GetLocalGroup"
    ,"GetNetAccounts"
    ,"GetTPM"
    ,"GetUSBActivity"
    ,"GetPNPDevices"
    ,"GetPNPDeviceProperties"
    ,"GetBiosInfo"
    ,"GetSMBShares"
    ,"GetBitlocker"
    ,"GetPSDrives"
    ,"GetLocalPorts"
    ,"GetPortsandProcesses"
    ,"GetWindowsCapability"
    ,"GetWindowsOptionalFeatures"
    ,"GetInstalledPrograms"
    ,"GetStartupPrograms"
    ,"GetScheduledTasks"
    ,"GetRunningServices"
    ,"GetWindowsUpdates"
    ,"GetHotFix"
    ,"GetGPResult"
    ,"GetEventLogList"
    ,"GetFirewallProfile"
    ,"GetFirewallRules"
    ,"GetVolumes"
    ,"GetDiskInfo"
    ,"GetHost"
    ,"GetAuditPol"
    ,"GetStoppedServices"
    ,"GetDependentServices"
    ,"GetDNSCache"
    ,"GetSecEdit"
    ,"GetComputerInfo"
    ,"GetSystemInfo"
    #,"GetDriverHash"
    #,"GetHiddenFiles"
    ,"LaunchNotepad"        
)

#Requires -RunAsAdministrator

$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

## VARIABLES
# Gets Domain Name
# Added 1/7/21 PowerShell 7.2.1 Compatibility Get-WmiObject not compatible with PowerShell 7.2.1
#$DomainName = (Get-WmiObject win32_computersystem).domain
$DomainName = (Get-CimInstance Win32_ComputerSystem).Domain

# Returns ComputerName
$ComputerName = $env:computername

# Logpath where reports will be generated, UNC path is acceptable.
$logpath = "C:\COD-Logs\$ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
#$logpath = "\\SERVERNAME\SHARENAME\COD-Logs\$ComputerName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }
# Added 1/7/21 PowerShell 7.2.1 Compatibility for Out-File not printing escape characters
if ($PSVersionTable.PSVersion.major -ge 7) {$PSStyle.OutputRendering = 'PlainText'}

# Name and Location of the Master Report File
$OutputFile = "$logpath\Master.log"

# Counter Used fir Write-Progress
$Counter = 0

## End of Variables

#Sets Header information for the Reports
    Write-Output "POWERSHELL ASSESSMENT SCRIPT" | out-file -Append $OutputFile
    Get-Date | out-file -Append $OutputFile


Write-Output "Computer Name: "| out-file -Append $OutputFile
    if ((Get-CimInstance win32_computersystem).partofdomain -eq $true) 
    {
        Write-Output "$ComputerName.$DomainName is Joined to a Domain."| out-file -Append $OutputFile
        write-host -fore green "Script is Running"
        } else {
        Write-Output "$computername is NOT Joined to a Domain but part of $DomainName." | out-file -Append $OutputFile
    }

Measure-Command {   
###################################################################################################################################################################
Function GetEvaluateSTIG 
{
    If (-Not(Test-Path -Path "$localpath\evaluate-stig-master")) {
        Write-Output "Unable to Locate Evaluate-STIG.ps1 in path $localpath\evaluate-stig-master\PowerShell\Src\Evaluate-STIG\" | out-file -Append $OutputFile
    }
    Else {
    Try {If (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq 'D73CA91102A2204A36459ED32213B467D7CE97FB') {Write-Host 'DoD Root CA 3 certificate is already imported to Local Machine\Root store.' -ForegroundColor Cyan} Else {Import-Certificate $localpath\evaluate-stig-master\PowerShell\Src\Evaluate-STIG\Prerequisites\Certificates\DoD_Root_CA_3.cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null; Write-Host 'DoD_Root_CA_3.cer successfully imported to Local Machine\Root store.' -ForegroundColor Green}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}
    Try {If (Get-ChildItem Cert:\LocalMachine\CA | Where-Object Thumbprint -eq '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7') {Write-Host 'DOD ID CA-59 certificate is already imported to Local Machine\CA.' -ForegroundColor Cyan} Else {Import-Certificate $localpath\evaluate-stig-master\PowerShell\Src\Evaluate-STIG\Prerequisites\Certificates\DOD_ID_CA-59.cer -CertStoreLocation Cert:\LocalMachine\CA | Out-Null; Write-Host 'DOD_ID_CA-59.cer successfully imported to Local Machine\CA.' -ForegroundColor Green}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}
    Try {If (Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -eq 'D95F944E33528DC23BEE8672D6D38DA35E6F0017') {Write-Host 'CS.NSWCCD.001 certificate is already imported to Local Machine\Trusted Publishers store.' -ForegroundColor Cyan} Else {Import-Certificate $localpath\evaluate-stig-master\PowerShell\Src\Evaluate-STIG\Prerequisites\Certificates\CS.NSWCCD.001.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null; Write-Host 'CS.NSWCCD.001.cer successfully imported to Local Machine\Trusted Publishers store.' -ForegroundColor Green}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}

    & "$localpath\evaluate-stig-master\PowerShell\Src\Evaluate-STIG\Evaluate-STIG.ps1" -ScanType Classified -OutputPath $logpath

    # Run Summary Report from Evaluate STIG
    GetStigSummary

    # Run Detail Open Items Report from Evaluate STIG
    GetSTIGDetail
    
    }
}
Function GetStigSummary 
    {
    $reportpath = "$logpath\$env:computername\SummaryReport.xml"
    [xml]$xmlData = Get-Content -Path $reportpath
    $output = $xmlData.Summary.Checklists.ChildNodes | ForEach-Object {
        [pscustomobject]@{
            STIG = $_.STIG
            CAT_I_O = $_.CAT_I.Open
            CAT_II_O = $_.CAT_II.Open
            CAT_III_O = $_.CAT_III.Open
         }
    }
    Write-Output "GetStigSummary from Evaluate STIG" | out-file -Append $OutputFile
    $output | Out-File -Append $OutputFile
    }

Function GetSTIGDetail 
    {
    $reportpath = "$logpath\$env:computername\SummaryReport.xml"
    [xml]$xmlData = Get-Content -Path $reportpath
    $objs = @()
    $ChkFiles = $xmlData.SelectNodes("//Checklist//Vuln[@Status = 'Open']")

        foreach ($ChkFile in $ChkFiles)
        {
            $obj = new-object psobject -prop @{
                CklFile = $ChkFile.ParentNode.ParentNode.STIG
                RuleTitle =  "(" + $ChkFile.ID +") " + $ChkFile.RuleTitle
            } 
            $objs += $obj;
        }  
        Write-Output "GetStigDetails from Evaluate STIG" | out-file -Append $OutputFile
        $objs | Out-File -Append $OutputFile
    }
    Function GetFirewallProfile
{
    Write-Output "Firewall Profiles" | out-file -Append $OutputFile
    Get-NetFirewallProfile  | out-file -Append $OutputFile
}
Function GetDiskInfo 
{
    Write-Output "Disk Information, Check for Disk - IsBoot = Yes then Partition should be GPT. If not GPT secureboot more than likely is off " | out-file -Append $OutputFile
    Get-Disk | Select-Object DiskNumber, PartitionStyle, ProvisionintType, OperationalStatus,HealthStatus, BusType, BootFromDisk, FriendlyName, IsBoot, Manufacture, Model, NumberofPartitions, SerialNumber| Format-List | out-file -Append $OutputFile
}
Function GetScheduledTasks 
{
    Write-Output "Get-ScheduledTask - Are there tasks not Approved and not used in a Closed Environment?" | out-file -Append $OutputFile
    Get-ScheduledTask | out-file -Append $OutputFile
}
Function GetWindowsVersion 
{
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\"  | Select-Object ProductName, ReleaseID, InstallDate, CurrentBuild, DisplayVersion |
    Select-Object ProductName, ReleaseID, CurrentBuild, DisplayVersion,
        @{Name = 'InstallDate'; E = {(Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($_.InstallDate))}} | 
        Sort-Object ProductName, ReleaseID | Format-Table | out-file -Append $OutputFile
}	
Function GetExecutionPolicy 
{
    Write-Output "Show the PowerShell Execution Policy" | out-file -Append $OutputFile
    Get-ExecutionPolicy -List | out-file -Append $OutputFile
}
Function GetPowerShellVersion 
{
    Write-Output "PowerShell Version" | out-file -Append $OutputFile
    $PSVersionTable.PSVersion | out-file -Append $OutputFile
}
Function GetSystemInfo 
{
    Write-Output System Information | out-file -Append $OutputFile
    systeminfo | out-file -Append $OutputFile
}
Function GetPSDrives 
{
    Write-Output "Get-PSDrive"  | out-file -Append $OutputFile
    Get-PSDrive  | out-file -Append $OutputFile
}
Function GetVolumes 
{
    Write-Output "Get-Volume"  | out-file -Append $OutputFile
    Get-Volume  | out-file -Append $OutputFile
}
Function GetHost
{
    Write-Output "Get-Host"  | out-file -Append $OutputFile
    Get-Host  | out-file -Append $OutputFile
}
Function GetComputerInfo 
{
    Write-Output "Get-ComputerInfo"  | out-file -Append $OutputFile
    Get-ComputerInfo  | out-file -Append $OutputFile
}
Function GetStartupPrograms 
{
    Write-Output "Startup Programs - What is listed, What's Approved, What is running that should not be, Google, OneDrive, etc.."  | out-file -Append $OutputFile
    Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location  | out-file -Append $OutputFile
}
Function GetLocalUser 
{
    Write-Output "Get-LocalUsers - What local Users are present, If Group (ADMIN) how is the Password stored, do they audit local account usage?" | out-file -Append $OutputFile
    get-localuser | Where-Object enabled -EQ $True | Select-Object Name, Enabled, 
        @{Name = 'Last Logon'; E = {($_.LastLogon).ToString('MM/dd/yyyy')}},
        @{Name = 'Last Logon Days'; E = {(new-timespan -start $(Get-date $_.LastLogon) -end (get-date)).days}},
        @{Name = 'Password Set'; E = {($_.PasswordLastSet).ToString('MM/dd/yyyy')}},
        @{Name = 'Password Expires'; E = {($_.PasswordExpires).ToString('MM/dd/yyyy')}},
        @{name = 'Password Age'; E = {(new-timespan -start $(Get-date $_.PasswordLastSet) -end (get-date)).days}} | Format-Table | out-file -Append $OutputFile
}
Function GetLocalGroup 
{
    Write-Output "Get-LocalGroup"  | out-file -Append $OutputFile
    Get-LocalGroup | out-file -Append $OutputFile
}
Function GetLocalAdministrators 
{
    Write-Output "Get-LocalGroupMember Administrators"  | out-file -Append $OutputFile
    Get-LocalGroupMember Administrators | out-file -Append $OutputFile
}
Function GetInstalledPrograms 
{

    if (!(Test-Path HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall)) 
    {
        Write-Output "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall Path does not Exist"  | out-file -Append $OutputFile
    }
    else 
    {
        Write-Output "Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher" | out-file -Append $OutputFile    
        $(Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | out-file -Append $OutputFile)
    }

    if (!(Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall)) 
    {
        Write-Output "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall Path does not Exist"  | out-file -Append $OutputFile
    }
    else 
    {
        Write-Output "Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher" | out-file -Append $OutputFile
        $(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher | out-file -Append $OutputFile)
    }
}
Function GetRunningServices 
{
    Write-Output "Running Services" | out-file -Append $OutputFile
    Get-Service | where-object {$_.Status -eq "running"} | Format-Table -Autosize | out-file -Append $OutputFile
}	
Function GetStoppedServices 
{
    Write-Output "Stopped Services" | out-file -Append $OutputFile
    Get-Service | where-object {$_.Status -eq "stopped"} | Format-Table -Autosize | out-file -Append $OutputFile
}	
Function GetDependentServices 
{
    Write-Output "Services that have dependent services" | out-file -Append $OutputFile
    Get-Service | where-object {$_.DependentServices} | Format-List -property name, DependentServices, @{Label="NoOfDependentServices"; Expression={$_.dependentservices.count}} | out-file -Append $OutputFile	
}	
Function GetUSBActivity 
{
    if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR)) 
    {
        Write-Output "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR Path does not Exist"  | out-file -Append $OutputFile
    }
    Else
    {
        Write-Output "Show Recent USB Activity IN REG USBSTOR" | out-file -Append $OutputFile
        Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select-Object FriendlyName | out-file -Append $OutputFile
    }
    
    if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Enum\USB)) 
    {
        Write-Output "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USB Path does not Exist"  | out-file -Append $OutputFile
    }
    Else
    {
        Write-Output "Show Recent USB Activity in REG USB" | out-file -Append $OutputFile
        Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\* | Select-Object DeviceDesc,Service,Mfg | out-file -Append $OutputFile
    }
}	
Function GetDNSCache 
{
    Write-Output "Get-DNS Client Cache | Select-Object -Property Entry"  | out-file -Append $OutputFile
    Get-DnsClientCache | Select-Object -Property Entry  | out-file -Append $OutputFile
}	
Function GetPortsandProcesses 
{
    Write-Output "TCP Connections and their associated Owning Processes"  | out-file -Append $OutputFile
    Get-NetTCPConnection -State Established | Format-Table -Autosize  | out-file -Append $OutputFile
    
    Write-Output "TCP Connections Listening"  | out-file -Append $OutputFile
    Get-NetTCPConnection -State Listen | Format-Table -Autosize  | out-file -Append $OutputFile
}
Function GetTPM 
{
    Write-Output "Get-TPM"  | out-file -Append $OutputFile
    if (((Get-WindowsEdition -Online) | Select-Object Edition) -notmatch 'Standard')
    {
        Get-TPM | out-file -Append $OutputFile
    }
    Else
    {
    Write-Output "This version of Windows does not support TPM"  | out-file -Append $OutputFile
    }
}
Function GetWindowsUpdates1
{
    $wu = new-object -com “Microsoft.Update.Searcher”
    $totalupdates = $wu.GetTotalHistoryCount()
    $all = $wu.QueryHistory(0,$totalupdates)

        $OutputCollection=  @()
        Write-Output "Get Windows Updates"  | out-file -Append $OutputFile
        Foreach ($update in $all)

            {
            $string = $update.title
            $output = New-Object -TypeName PSobject
            $output | Add-Member NoteProperty "Date"  -Value $Update.Date
            $output | add-member NoteProperty “Title” -value $string

            $OutputCollection += $output
            }

        $OutputCollection | Where-Object Title -NotLike *KB2267602* | Sort-Object Date | Format-Table -AutoSize | out-file -Append $OutputFile
}
Function GetWindowsUpdates 
{
    $Session = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher = $Session.CreateUpdateSearcher()
    $historyCount = $Searcher.GetTotalHistoryCount()
    $Searcher.QueryHistory(0, $historyCount) | 
        Select-Object Date,
            @{name="Status"; expression=
                {switch($_.resultcode){
                    1 {"In Progress"}; 
                    2 {"Succeeded"}; 
                    3 {"Succeeded With Errors"};
                    4 {"Failed"}; 
                    5 {"Aborted"} }}}, 
            Title | Where-Object Title -NotLike *KB2267602* | Sort-Object Date | out-file -Append $OutputFile
}
Function GetSMBShares 
{
    Write-Output "Get Local Shares, Shares not Authorized on Workstations or the Root of System Drives" | out-file -Append $OutputFile
    Get-SmbShare | out-file -Append $OutputFile
}
Function GetBiosInfo 
{
    Write-Output "Get BIOS Information - Is the BIOS Current" | out-file -Append $OutputFile
    Get-ItemProperty -Path HKLM:\HARDWARE\DESCRIPTION\System\BIOS | Select-Object BaseBoardManufacturer, BaseBoardProduct, BaseBoardVersion, BIOSReleaseDate, BIOSVersion | Format-Table  | out-file -Append $OutputFile
}
Function GetWindowsCapability 
{
    Write-Output "Get-WindowsCapability -Name * -Online | Where-object state -like Installed" | out-file -Append $OutputFile
    Get-WindowsCapability -Name * -Online | Select-Object -Property DisplayName, State | Where-object state -like Installed | Select-Object DisplayName, State  | Sort-Object DisplayName, State | Format-Table | out-file -Append $OutputFile
}
Function GetWindowsOptionalFeatures
{
    Write-Output "Get-WindowsOptionalFeature -Online | Where-Object State -like Enabled" | out-file -Append $OutputFile
    Get-WindowsOptionalFeature -online | Select-Object FeatureName, State | Where-Object State -like Enabled | Select-Object FeatureName, State  | Sort-Object FeatureName, State | Format-Table | out-file -Append $OutputFile
}
Function GetPNPDevices 
{
    Write-Output "PNP Devices - See PNP Device Properties for Additional Details"  | out-file -Append $OutputFile
    Get-pnpdevice | Select-Object FriendlyName, Class | Select-Object FriendlyName, Class | Sort-Object Class, FriendlyName -Unique | Format-Table | out-file -Append $OutputFile
}
Function GetPNPDeviceProperties
{
    Write-Output "PNP Device Properties Open Link Below for Details"  | out-file -Append $OutputFile
    Write-Output "$Logpath\PNPDeviceProperties.txt"  | out-file -Append $OutputFile

    $InstanceIDs = Get-pnpdevice | Select-Object InstanceID, FriendlyName, Class | Where-Object Class -Notlike System | Where-Object Class -NotLike Volume* | Where-Object Class -NotLike PrintQueue | Where-Object Class -NotLike Processor | Where-Object Class -NotLike HIDClass
        
        foreach ($InstanceID in $InstanceIDs.instanceid) {
            Get-pnpdeviceproperty -KeyName 'DEVPKEY_Device_DeviceDesc', 'DEVPKEY_Device_Class', 'DEVPKEY_Device_FriendlyName', 'DEVPKEY_Device_EnumeratorName', 'DEVPKEY_Device_InstanceId', 'DEVPKEY_Device_FirstInstallDate', 'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_IsPresent' -InstanceId $InstanceID |
                Select-Object KeyName, Data | Format-Table | out-file -Append $Logpath\PNPDeviceProperties.txt   
        }
}
Function GetLocalPorts 
{
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | 
        Sort-Object Localaddress, LocalPort, RemoteAddress, RemotePort | Format-Table | out-file -Append $OutputFile
}
Function GetHotFix
{
    Write-Output "Get HotFixs" | out-file -Append $OutputFile
    Get-HotFix | Select-Object PSComputerName, Description, HotFixID, 
        @{Name = 'InstalledOn'; E = {($_.InstalledOn).ToString('MM/dd/yyyy')}},
        InstalledBy | Format-Table | out-file -Append $OutputFile
}
Function GetFirewallRules
{
    Write-Output "Enabled Firewall Rules" | out-file -Append $OutputFile
    Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, enabled | Where-Object enabled -eq true |
    Select-Object Direction, Action, DisplayName | Sort-Object DisplayName | Format-Table -AutoSize | out-file -Append $OutputFile
}
Function GetEventLogList 
{
    $Results = Get-WinEvent -ListLog * | Select-Object LogName, IsEnabled, Filesize, OldestRecordNumber, RecordCount
    
    Write-Output "Lists all Event Logs Enabled" | out-file -Append $OutputFile
    $Results | Select-Object LogName, IsEnabled, Filesize, OldestRecordNumber, RecordCount | Sort-Object IsEnabled, LogName | Where-Object IsEnabled -eq $true | Format-Table | out-file -Append $OutputFile

    Write-Output "Lists all Event Logs Not Enabled" | out-file -Append $OutputFile
    $Results | Select-Object LogName, IsEnabled | Sort-Object IsEnabled, LogName | Where-Object IsEnabled -eq $false | Format-Table | out-file -Append $OutputFile
}
Function GetBitlocker 
{
    if (((Get-WindowsEdition -Online) | Select-Object Edition) -notmatch 'Standard' )
    {
        $disk= Get-CimInstance -Query "Select * From win32_logicaldisk Where DriveType = '3'"
        foreach ( $drive in $disk ) 
        {
            Write-Output "Get-BitLockerVolume -MountPoint $drive.Name" | out-file -Append $OutputFile
            Get-BitLockerVolume -MountPoint $drive.Name | Format-List | out-file -Append $OutputFile
        }
    }
    Else
    {
    Write-Output "This Version does not support Bitlocker" | out-file -Append $OutputFile
    }
}
Function GetHiddenFiles 
{
    $disk= Get-CimInstance -Query "Select * From win32_logicaldisk Where DriveType = '3'"
    foreach ( $drive in $disk )
            {
                $drivename = $drive.Name +"\"
                Write-Output "$drivename -Recurse -Hidden -erroraction 'silentlycontinue' " | out-file -Append $OutputFile
                Get-ChildItem $drivename -Recurse -Hidden -erroraction 'silentlycontinue' | out-file -Append $OutputFile
            }
}    
Function GetDriverHash
{
    $stdout = "$logpath\$(get-date -format "yyyyMMdd-hhmmss").log"
    Get-ChildItem C:\windows\system32\drivers -Recurse | Get-FileHash | Select-Object -Property Hash, Path | Format-Table -HidetableHeaders -Autosize  | out-file -Append $stdout
    Get-ChildItem C:\windows\SysWOW64 -Recurse | Get-FileHash | Select-Object -Property Hash, Path | Format-Table -HidetableHeaders -Autosize  | out-file -Append $stdout

    Write-Output "Driver Hash Values" | out-file -Append $OutputFile
    Get-Content $stdout | Out-File -Append $OutputFile
    Remove-Item $stdout
}
Function GetAuditPol 
{
    $auditpol = "auditpol.exe"
    $arguments = "/get /category:*"
    $stdout = "$logpath\$(get-date -format "yyyyMMdd-hhmmss").log"

        Write-Output "AuditPol.exe /get /category:* if STIG compliant, Account Management / Security Group Management for Success and Failure" | out-file -Append $OutputFile
        Start-Process $auditpol $arguments -NoNewWindow -Wait -RedirectStandardOutput $stdout
        Get-Content $stdout | Out-File -Append $OutputFile
        Remove-Item $stdout
}
Function GetSecEdit 
{
    $command = "secedit.exe"
    $stdout = "$logpath\$(get-date -format "yyyyMMdd-hhmmss").log"
    $arguments = "/export /areas SECURITYPOLICY /cfg $stdout"

        Write-Output "SecEdit.exe /export /areas SECURITYPOLICY /cfg" | out-file -Append $OutputFile
        Start-Process $command $arguments -NoNewWindow -wait
        Get-Content $stdout | Out-File -Append $OutputFile
        Remove-Item $stdout
}
Function GetNetAccounts
{
    $command = "net.exe"
    $stdout = "$logpath\$(get-date -format "yyyyMMdd-hhmmss").log"
    $arguments = "Accounts"

        Write-Output "Net Accounts Configuration Policy" | out-file -Append $OutputFile
        Start-Process $command $arguments -NoNewWindow -wait -RedirectStandardOutput $stdout
        Get-Content $stdout | Out-File -Append $OutputFile
        Remove-Item $stdout
}
Function GetGPResult 
{
    $command = "gpresult.exe"
    $stdout = "$logpath\$(get-date -format "yyyyMMdd-hhmmss").log"
    $arguments = "/R"

        Write-Output "GPResult - What Domain Group Policies are being Applied to the System" | out-file -Append $OutputFile
        Start-Process $command $arguments -NoNewWindow -wait -PassThru -RedirectStandardOutput $stdout
        Get-Content $stdout | out-file -Append $OutputFile
        Remove-Item $stdout
}
Function LaunchNotepad 
{
    Start-Process Notepad.exe $OutputFile -NoNewWindow
}

# Runs all Tasks within the Parameters provided
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

Get-Date | out-file -Append $OutputFile
write-host -fore green "Results saved to: $OutputFile" 
write-host -fore green "Script Completed"
}

