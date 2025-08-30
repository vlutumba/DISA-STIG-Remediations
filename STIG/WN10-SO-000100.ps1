 <#
.SYNOPSIS
    This PowerShell script ensures that the Windows SMB client is configured to always perform SMB packet signing.

.NOTES
    Author          : Vilfride Lutumba
    LinkedIn        : linkedin.com/in/vlutumba/
    GitHub          : github.com/vlutumba
    Date Created    : 2025-08-30
    Last Modified   : 2025-08-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000100

.TESTED ON
    Date(s) Tested  : 2025-08-30
    Tested By       : Vilfride Lutumba
    Systems Tested  : Windows 10 Pro 22H2
    PowerShell Ver. : 5.1 build 19041 Rev. 6216

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN10-SO-000100.ps1 
#>

# Define the registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$valueName = "RequireSecuritySignature"
$valueData = 1  # 0x00000001 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the RequireSecuritySignature value (0x00000001 = 1 in decimal)
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName
