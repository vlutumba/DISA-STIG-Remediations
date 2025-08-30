 <#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Vilfride Lutumba
    LinkedIn        : linkedin.com/in/vlutumba/
    GitHub          : github.com/vlutumba
    Date Created    : 2025-08-30
    Last Modified   : 2025-08-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 2025-08-30
    Tested By       : Vilfride Lutumba
    Systems Tested  : Windows 10 Pro 22H2
    PowerShell Ver. : 5.1 build 19041 Rev. 6216

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AU-000500.ps1 
#>

# Define the registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 32768  # 0x00008000 in hexadecimal

# Define the registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the MaxSize value (0x8000 = 32768 in decimal)
Set-ItemProperty -Path $regPath -Name "MaxSize" -Value 0x8000 -Type DWord

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object MaxSize
