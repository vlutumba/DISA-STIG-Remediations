 <#
.SYNOPSIS
    This PowerShell script ensures that the Windows 10 account lockout duration is configured to 15 minutes or greater.

.NOTES
    Author          : Vilfride Lutumba
    LinkedIn        : linkedin.com/in/vlutumba/
    GitHub          : github.com/vlutumba
    Date Created    : 2025-08-31
    Last Modified   : 2025-08-31
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 2025-08-31
    Tested By       : Vilfride Lutumba
    Systems Tested  : Windows 10 Pro 22H2
    PowerShell Ver. : 5.1 build 19041 Rev. 6216

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AC-000005.ps1 
#>

# Run in an elevated PowerShell window
$currentLockoutDuration = (cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout duration' } | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() })
$newLockoutDuration = 15   # Use 0 if you want "until an admin unlocks" (also compliant)


# Set Lockout duration to 15 minutes
if ($currentLockoutDuration -ne 0 -and $currentLockoutDuration -lt 15) { 

cmd /c "net accounts /lockoutduration:$newLockoutDuration" | Out-Null

 }
 
# Verify the value
cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout duration' }
