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



# STIG-ID: WN10-CC-000030
# The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.# Define the registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$valueName = "EnableICMPRedirect"
$valueData = 0  # (0x00000001 (0))
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the EnableICMPRedirect value (0x00000000 (0))
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000050
# Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$valueName1 = "\\*\NETLOGON" # RequireMutualAuthentication=1, RequireIntegrity=1
$valueName2 = "\\*\SYSVOL" # RequireMutualAuthentication=1, RequireIntegrity=1
$valueData = 1 
$valueType = "String"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the values
Set-ItemProperty -Path $regPath -Name $valueName1 -Value $valueData -Type $valueType
Set-ItemProperty -Path $regPath -Name $valueName2 -Value $valueData -Type $valueType


# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName1, $valueName2



# STIG-ID: WN10-CC-000052
# Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$valueName = "EccCurves"
$valueData = "NistP384","NistP256"
$valueType = "MultiString"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the EccCurves value
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

# Set the DCSettingIndex value (0x00000001 (1))
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

# Set the AllowTelemetry value (0x00000001 (1))
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



# STIG-ID: WN10-CC-000335
# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$valueName = "EnumerateAdministrators"
$valueData = 0  # 0x00000000 in hexadecimal
$valueType = "DWord"

# Make sure the path exists
If (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the EnumerateAdministrators value (0x00000000 = 0 in decimal)
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

# Set the AllowDigest value (0x00000000 (0))
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName



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

# Set the AllowDomainPINLogon value (0x00000000 (0))
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

# Set the FilterAdministratorToken value (0x00000001 (1))
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

# Set the ConsentPromptBehaviorAdmin value (0x00000002 (2))
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type $valueType

# Verify the value
Get-ItemProperty -Path $regPath | Select-Object $valueName
