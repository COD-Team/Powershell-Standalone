<#
    .DESCRIPTION
        Protecting file integrity is critical so we do not introduce anything malicous, after performing virus scan 
        and the last step before burning media, this script performs a HASH (SHA256) and File List of all files, then 
        saves to root of the path. 
        
        After the HASH and File list is complete, it copies them as CSV files into that root. 
    
    .PARAMETER
        Path to Files you need to HASH and Create a File Listing
    
    .EXAMPLE
        Command Prompt (Admin) "powershell -ExecutionPolicy Bypass -File PATH\GetHashList.ps1 "PathToHash"

    .NOTES
    
    .LINK
        https://github.com/COD-Team
  
    .FUNCTIONALITY
        PowerShell Language

#>


param (
    [string]$path
)

# Performs HASH and FileList, stores to Memory
$hashout = Get-ChildItem -Path $path -Recurse | Get-FileHash
$fileout = Get-ChildItem -Path $path -Recurse | Select-Object Mode, Directory, Name, Length, LastWriteTime

# Retrieves from list from memory and exports to CSV files
$hashout | Export-Csv $path\hash.csv
$fileout | Export-CSV $path\FileList.csv -NoTypeInformation

write-host -fore green "Results saved to: $Path" 
write-host -fore green "Script Completed"
