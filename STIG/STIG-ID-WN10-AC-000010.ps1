 <#
.SYNOPSIS
    This PowerShell script ensures that the number of allowed bad logon attempts is configured to 3 or less.

.NOTES
    Author          : Vilfride Lutumba
    LinkedIn        : linkedin.com/in/vlutumba/
    GitHub          : github.com/vlutumba
    Date Created    : 2025-09-01
    Last Modified   : 2025-09-01
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000010

.TESTED ON
    Date(s) Tested  : 2025-09-01
    Tested By       : Vilfride Lutumba
    Systems Tested  : Windows 10 Pro 22H2
    PowerShell Ver. : 5.1 build 19041 Rev. 6216

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AC-000010.ps1 
#>

# Run in an elevated PowerShell window
[int]$currentLockoutThreshold = (cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout threshold' } | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() })
[int]$newLockoutThreshold = 3   # Use 1-3, 0 is unacceptable)


# Set Lockout threshold to 3
if ($currentLockoutThreshold -eq 0 -or $currentLockoutThreshold -gt 3) { 

cmd /c "net accounts /lockoutthreshold:$newLockoutThreshold" | Out-Null

 }
 
# Verify the value
cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout threshold' }
