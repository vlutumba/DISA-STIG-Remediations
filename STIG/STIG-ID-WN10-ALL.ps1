<#
.SYNOPSIS
    This PowerShell script applies multiple Windows 10 Security Technical Implementation Guide (STIG) settings 
    by configuring several critical security controls.

.NOTES
    Author          : Vilfride Lutumba
    LinkedIn        : linkedin.com/in/vlutumba/
    GitHub          : github.com/vlutumba
    Date Created    : 2025-09-01
    Last Modified   : 2025-09-01
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A    

.TESTED ON
    Date(s) Tested  : 2025-09-01
    Tested By       : Vilfride Lutumba
    Systems Tested  : Windows 10 Pro 22H2
    PowerShell Ver. : 5.1 build 19041 Rev. 6216

.USAGE
    Example syntax:
    PS C:\> .\STIG-ID-WN10-ALL.ps1
    
    List all STIGS: 
    PS C:\> Get-Content .\STIG-ID-WN10-ALL.ps1 | Select-String -Pattern "WN10-" | ForEach-Object { ($_ -split '\s+') -match '^WN10-'} | Sort-Object

#>

# STIG-ID: WN10-00-000032
# Windows 10 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$valueName = "MinimumPIN"
$valueData = 6  # (0x00000006 (6) or greater)
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the MinimumPIN value (0x00000006 (6) or greater)
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName


# STIG ID: WN10-AC-000005
# Windows 10 account lockout duration must be configured to 15 minutes or greater.
# Run in an elevated PowerShell window
$currentLockoutDuration = (cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout duration' } | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() })
$newLockoutDuration = 15   # Use 0 if you want "until an admin unlocks" (also compliant)


# Set Lockout duration o 15 minutes
if ($currentLockoutDuration -ne 0 -and $currentLockoutDuration -lt 15) { 

cmd /c "net accounts /lockoutduration:$newLockoutDuration" | Out-Null

 }
 
# Verify the value
cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout duration' }



# STIG ID: WN10-AC-000010
# The number of allowed bad logon attempts must be configured to 3 or less.
# Run in an elevated PowerShell window
[int]$currentLockoutThreshold = (cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout threshold' } | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() })
[int]$newLockoutThreshold = 3   # Use 1-3, 0 is unacceptable)


# Set Lockout threshold to 3
if ($currentLockoutThreshold -eq 0 -or $currentLockoutThreshold -gt 3) { 

cmd /c "net accounts /lockoutthreshold:$newLockoutThreshold" | Out-Null

 }
 
# Verify the value
cmd.exe /c 'net accounts' | Where-Object { $_ -match 'Lockout threshold' }



# STIG ID: WN10-AU-000500
# The Application event log size must be configured to 32768 KB or greater.
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

# Set the value
Set-ItemProperty -Path $regPath -Name "MaxSize" -Value 0x8000 -Type DWord

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object MaxSize



# STIG ID: WN10-CC-000005
# Camera access from the lock screen must be disabled.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenCamera"
$valueData = 1  # 0x00000001 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000030
# The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.# Define the registry path and value
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$valueName = "EnableICMPRedirect"
$valueData = 0  # (0x00000000 (0))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000035
# The system must be configured to ignore NetBIOS name release requests except from WINS servers.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
$valueName = "NoNameReleaseOnDemand"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000050
# Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$valueName1 = "\\*\NETLOGON" # RequireMutualAuthentication=1, RequireIntegrity=1
$valueData1 = "RequireMutualAuthentication=1, RequireIntegrity=1" 
$valueName2 = "\\*\SYSVOL" # RequireMutualAuthentication=1, RequireIntegrity=1
$valueData2 = "RequireMutualAuthentication=1, RequireIntegrity=1" 
$valueType = "String"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the values
Set-ItemProperty -Path $regPath -Name $valueName1 -Value $valueData1 -Type $valueType
Set-ItemProperty -Path $regPath -Name $valueName2 -Value $valueData2 -Type $valueType


# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName1, $valueName2



# STIG-ID: WN10-CC-000052
# Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$valueName = "EccCurves"
$valueData = "NistP384","NistP256"
$valueType = "MultiString"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000090
# Group Policy objects must be reprocessed even if they have not changed.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valueName = "NoGPOListChanges"
$valueData = 0  # (0x00000000 (0))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000105
# Web publishing and online ordering wizards must be prevented from downloading a list of providers.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoWebServices"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000145
# Users must be prompted for a password on resume from sleep (on battery).
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$valueName = "DCSettingIndex"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000165
# Unauthenticated RPC clients must be restricted from connecting to the RPC server.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$valueName = "RestrictRemoteClients"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG ID: WN10-CC-000197
# Microsoft consumer experiences must be turned off.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableWindowsConsumerFeatures"
$valueData = 1  # 0x00000001 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG ID: WN10-CC-000200
# Administrator accounts must not be enumerated during elevation.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$valueName = "EnumerateAdministrators"
$valueData = 0  # 0x00000000 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000205
# Windows Telemetry must not be configured to Full.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName = "AllowTelemetry"
$valueData = 1  # (0x00000000 (0) - Security), (0x00000001 (1) - Basic)
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000230
# Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$valueName = "PreventOverride"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000275
# Local drives must be prevented from sharing with Remote Desktop Session Hosts.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fDisableCdm"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000310
# Users must be prevented from changing installation options.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\Policies\Microsoft\Windows\Installer"
$valueName = "EnableUserControl"
$valueData = 0  # (0x00000000 (0))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000325
# Automatically signing in the last interactive user after a system-initiated restart must be disabled.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "DisableAutomaticRestartSignOn"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000335
# The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$valueName = "EnumerateAdministrators"
$valueData = 0  # 0x00000000 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000355
# The Windows Remote Management (WinRM) service must not store RunAs credentials.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "DisableRunAs"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000360
# The Windows Remote Management (WinRM) client must not use Digest authentication.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowDigest"
$valueData = 0  # (0x00000000 (0))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG ID: WN10-CC-000365
# Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
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

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName1 -Value $valueData -Type $valueType
Set-ItemProperty -Path $regPath -Name $valueName2 -Value $valueData -Type $valueType


# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName1, $valueName2



# STIG-ID: WN10-CC-000370
# The convenience PIN for Windows 10 must be disabled.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$valueName = "AllowDomainPINLogon"
$valueData = 0  # (0x00000000 (0))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000327
# PowerShell Transcription must be enabled on Windows 10.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$valueName = "EnableTranscripting"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the EnableTranscripting value (0x00000001 (1))
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG ID: WN10-SO-000100
# The Windows SMB client must be configured to always perform SMB packet signing.
# Define the registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$valueName = "RequireSecuritySignature"
$valueData = 1  # 0x00000001 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-SO-000245
# User Account Control approval mode for the built-in Administrator must be enabled.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "FilterAdministratorToken"
$valueData = 1  # (0x00000001 (1))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-SO-000250
# User Account Control must, at minimum, prompt administrators for consent on the secure desktop.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "ConsentPromptBehaviorAdmin"
$valueData = 2  # (Prompt for consent on the secure desktop)
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG ID: WN10-SO-000255
# User Account Control must automatically deny elevation requests for standard users.
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "ConsentPromptBehaviorUser"
$valueData = 0  # 0x00000000 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName
