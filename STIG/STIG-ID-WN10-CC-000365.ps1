 <#
.SYNOPSIS
    This PowerShell script ensures that the Windows Remote Management (WinRM) client does not allow unencrypted traffic.

.NOTES
    Author          : Vilfride Lutumba
    LinkedIn        : linkedin.com/in/vlutumba/
    GitHub          : github.com/vlutumba
    Date Created    : 2025-09-01
    Last Modified   : 2025-09-01
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000365

.TESTED ON
    Date(s) Tested  : 2025-09-01
    Tested By       : Vilfride Lutumba
    Systems Tested  : Windows 10 Pro 22H2
    PowerShell Ver. : 5.1 build 19041 Rev. 6216

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000365.ps1 
#>

# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$valueName1 = "LetAppsActivateWithVoiceAboveLock"
$valueName2 = "LetAppsActivateWithVoice"
$valueData = 2  # 0x00000002 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value(s) (0x00000002 = 2 in decimal)
Set-ItemProperty -Path $regPath -Name $valueName1 -Value $valueData -Type $valueType
Set-ItemProperty -Path $regPath -Name $valueName2 -Value $valueData -Type $valueType


# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName1, $valueName2
