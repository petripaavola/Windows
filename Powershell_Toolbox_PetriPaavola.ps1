# Powershell_toolbox_PetriPaavola.ps1
# 20190506
#
# Collection of Powershell-commands, tips and tricks mostly related to Windows management
#
# Yes, this is HUGE script and it will not get smaller. Use search to find interesting stuff.
# Everything should work :) I update this regurlarly as this is the script I'm also using personally.
#
# Petri.Paavola@yodamiitti.fi
# Microsoft MVP - Windows and Devices for IT
#
# This script came from
# https://github.com/petripaavola/Windows


# Just to make sure we will NEVER ever run this script
Write-Host "Do NOT ever ever ever EVER try to run me!" -Foregroundcolor "Red"
Pause
Exit


############################################################

# Check executionpolicies status
Get-ExecutionPolicy -list

# Set executionpolicy bypass for different scopes

# Allow running Powershell scripts
# These does NOT need Admin rights
Set-ExecutionPolicy -ExecutionPolicy bypass -Scope Process
Set-ExecutionPolicy -ExecutionPolicy bypass -Scope CurrentUser

# Allow running Powershell scripts machine wide
# Need Admin rights
Set-ExecutionPolicy -ExecutionPolicy bypass -Scope LocalMachine
Set-ExecutionPolicy -ExecutionPolicy bypass
Set-ExecutionPolicy bypass


# Bypass Powershell executionpolicies. This bypasses enforced signature requirement
# Run Powershell file line by line as commands
powershell.exe -noprofile -command " & { get-content C:\temp\Powershell\Bypass_executionpolicy.ps1 | foreach { if($_ -ne '') { iex $_ } } } "

############################################################

# Powershell ISE
$psise

############################################################

# Show Powershell-version
$PSVersionTable
$PSVersionTable.PSVersion

# Powershell home folder
Set-Location $pshome


# List files in directory (dir / ls)
Get-ChildItem c:\

# Get folder size (and subfolders)
Get-ChildItem C:\temp | Measure-Object -Sum Length

# Get folder/directory size (and subfolders) recursively
(Get-ChildItem -Recurse C:\temp | Measure-Object -Sum Length).Sum

# Get folder/directory size (and subfolders) recursively. Show gigabytes
(Get-ChildItem -Recurse C:\temp | Measure-Object -Sum Length).Sum / 1gb

# Get folder/directory size (and subfolders) recursively. Round gigabytes without decimals
[math]::Round((Get-ChildItem -Recurse C:\temp | Measure-Object -Sum Length).Sum / 1gb)



# Get computer processes
Get-Process
Get-Process csrss

$process = Get-Process explorer -IncludeUserName
$process.UserName

Get-Process explorer -IncludeUserName | Select-Object -ExpandProperty UserName

######
# Process wmi has GetOwner()

$explorerprocesses = @(Get-WmiObject -Query "Select * FROM Win32_Process WHERE Name='explorer.exe'" -ErrorAction SilentlyContinue)
if ($explorerprocesses.Count -eq 0) {
    "No explorer process found / Nobody interactively logged on"
}
else {
    foreach ($i in $explorerprocesses) {
        $Username = $i.GetOwner().User
        $Domain = $i.GetOwner().Domain
        $Domain + "\" + $Username + " logged on since: " + ($i.ConvertToDateTime($i.CreationDate))
    }
}
######

# Get services
Get-Service
Get-Service BITS

# Restart BITS
Get-Service BITS | Restart-Service

# Get Disk Information
Get-Disk
Get-Disk 0

# Get Network-adapter
Get-NetAdapter



# Get ComputerInfo. Look alias (alias gin)
Get-ComputerInfo



# List aliases
alias
alias cd

# Create alias
New-Alias np c:\windows\notepad.exe

# If we need more complex aliases create Function to Powershell profile
notepad.exe $profile



# Help
Get-Help cmdlet
Get-Help get-process
Get-Help get-process -examples
Get-Help get-process -detailed
Get-Help get-process -full

# Update-help, requires network connection.
Update-Help

# Load help for offline usage
Save-Help

# Load offline helps
Update-Help -SourcePath C:\temp\Powershell\helps

# Show Graphical Help
Show-Command


# Show Cmdlets
Get-Command
Get-Command Get-Pr*

# How many Cmdlets exists
Get-Command | Measure-Object

Get-Command | Out-File .\Get-Command.txt

# Open Get-Command.txt with default software associated with .txt
# Invoke-Item always opens with default file association
Invoke-Item .\Get-Command.txt
np .\Get-Command.txt


# Powershell-documentation
Get-Help about*
Get-Help about_aliases


# Show modulepath
$env:PSModulePath

# Show paths in each line on it's own row
($env:PSModulePath).Split(';')

# Show previous commands
Get-History
Get-History 10
# Alias h

# Type #number and tab to extract history command to command line
# Thanks Jere for tip ;)


# Show information about object
| Get-Member
Get-Process | Get-Member
Get-Process | Get-Member
"foobar" | Get-Member

# Visualize object graphically with Out-GridView
Out-GridView
Get-Process | Out-GridView

# Show all attributes in Out-GridView
Get-Process | Select-Object -Property * | Out-GridView

# This shown less information
Get-Process | Format-List

# This shows all object's attributes
Get-Process | Format-List *


# Select-object, show first
Get-Process | Select-Object -First 1

# Get newest file which is written in directory
Get-ChildItem c:\Powershell -File | Sort-Object LastWriteTime | Select-Object -last 1

# Get newest folder which has been written
#Hae uusin Hakemisto joka on kirjoitettu
Get-ChildItem c:\Powershell -Directory | Sort-Object LastWriteTime | Select-Object -last 1

# Count of something
Get-Command | Measure-Object
(Get-Command | Measure-Object).Count

# Set ReadOnly for files in folder
Get-ChildItem C:\Powershell\Foreach\ -File | ForEach-Object { Set-ItemProperty $_.Fullname -Name IsReadOnly -Value $true }

# Set ReadOnly for last written file
Get-ChildItem C:\Powershell\Foreach\ -File | Sort-Object LastWriteTime | Select-Object -last 1 | ForEach-Object { Set-ItemProperty $_.Fullname -Name IsReadOnly -Value $true }

# Show files which have ReadOnly bit set (IsReadOnly -attribute)
Get-ChildItem C:\Powershell\Foreach\ -File | Where-Object { $_.IsReadOnly -eq 'True' }

Get-ChildItem C:\Powershell\Foreach\ | Out-File .\FilesInDirectory.txt

# Rename multiple file extensions with regexp/replace (.txt -> .log)
Get-ChildItem *.txt | Rename-Item -NewName { $_.name -Replace '\.txt$', '.log' }
Get-ChildItem C:\Powershell\rename\*.txt | Rename-Item -NewName { $_.name -Replace '\.txt$', '.log' }

# Rename multiple file names with regexp/replace
Get-ChildItem C:\Powershell\rename\*.log | Rename-Item -NewName { $_.name -Replace 'History', 'Foobar' }


########## Variables ##########

# Check if variable is int, array, string, ... - isarray
$a -is [array]
$var -is [int]
'foo' -is [string]

########## Variables ##########

########## Powershell providers PS-Provider ##########

Get-PSProvider


# Get drives
Get-PSDrive

# Get C: -drive used space. Show gigabytes
(Get-PSDrive -Name C).Used / 1gb

# Get C: -drive used space. Round and show gigabytes with 2 decimals
[math]::Round(((Get-PSDrive -Name C).Used / 1gb), 2)

# Get C: -drive used space. Round and show gigabytes without decimals
[math]::Round((Get-PSDrive -Name C).Used / 1gb)

########## Powershell providers PS-Provider ##########



########## WMI, gwmi, Get-WmiObject, Get-CimInstance, gcim ##########

# We should change our command from Get-WmiObject (gwmi) to Get-CimInstance (gcim)

# HP EliteDesk 800 G3 DM 35W
# HP EliteDesk 800 G3 SFF
# Test if this query is true on Task Sequence run condition
Get-WmiObject -Query 'Select * FROM Win32_ComputerSystem WHERE Model Like "%EliteDesk 800 G3%"'

# HP ZBook Studio G3
# Test if this query is true on Task Sequence run condition
Get-WmiObject -Query 'Select * FROM Win32_ComputerSystem WHERE Model Like "%ZBook Studio G3%"'


(Get-WmiObject win32_battery).estimatedChargeRemaining
(Get-WmiObject win32_battery).EstimatedRunTime

# Check if we are running on battery or not
# 1 running on battery 
# 2 connected to AC
Get-WmiObject Win32_Battery | Select -ExpandProperty BatteryStatus


# Check if we are running in battery in Task Sequence
#
# Running on battery
Get-WmiObject -Query 'Select * FROM Win32_Battery WHERE BatteryStatus Like "1"'

# Running on AC
Get-WmiObject -Query 'Select * FROM Win32_Battery WHERE BatteryStatus Like "2"'


###########################

$Win32battery = Get-WmiObject Win32_Battery
# This does not exist on desktop computers
if ($Win32battery) {
	# Win32_battery exist

    if ($Win32battery.BatteryStatus -eq 1) {
        Write-Host "Laptop running on battery (AC not connected)"
    }

    if ($Win32battery.BatteryStatus -eq 2) {
        Write-Host "Laptop running on AC"
    }
}
else {
    # Did not find Win32_Battery    
}

###########################


# TPM32 WMI
Get-CimInstance -namespace root\cimv2\security\microsofttpm -class Win32_Tpm

# Export computer information to xml-files
$Manufacturer = (Get-WmiObject -Class win32_computersystem).Manufacturer
$Model = (Get-WmiObject -Class win32_computersystem).Model
Get-WmiObject Win32_ComputerSystem | Export-Clixml -Path ".\$Manufacturer $Model - Win32_ComputerSystem.xml"
Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\WMI | Export-Clixml -Path ".\$Manufacturer $Model - MS_SystemInformation.xml"

# Show Installed Applications
Get-CimInstance Win32_Product
Get-CimInstance Win32_Product | Format-List *

Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*softwarename*" } | Format-List *

# Get MSI package ProductCode
Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*software*" } | Select-Object -ExpandProperty identifyingnumber

# If the OEM key in the BIOS or firmware of the device must be used, run the following PowerShell command to get the key:
Get-CimInstance SoftwareLicensingService | Select-Object -ExpandProperty OA3xOriginalProductKey


# Uninstall MSI software
# Foreach is used here just to get ProductCode value to msiexec-command as parameter. Msiexec does NOT understand pipeline so Foreach is workaround for getting value into variable
# -outvariable ProductCode could be used too, but then it is NOT oneliner anymore :)

# TEST WHAT WOULD BE Removed
# All Application by name, find dynamically from WMI and remove MSI-software
Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*softwarename*" } | Select-Object -expandproperty identifyingnumber | ForEach-Object { Write-Host "msiexec /x $_" }

# Remove First Application by name, find dynamically from WMI and remove MSI-software
Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*softwarename*" } | Select-Object -expandproperty identifyingnumber -First 1 | ForEach-Object { & msiexec.exe /x $_ }

# Remove All MSI Application by name, find dynamically from WMI and remove MSI-software
Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*softwarename*" } | Select-Object -expandproperty identifyingnumber | ForEach-Object { & msiexec.exe /x $_ }

########## WMI, gwmi, Get-WmiObject, Get-CimInstance End ##########

########## BIOS / UEFI ##########

# Good blog post about BIOS/UEFI and Powershell
# http://www.systanddeploy.com/2019/03/list-and-change-bios-settings-with.html


# Get HP BIOS/UEFI -settings
Get-WmiObject -namespace root/hp/instrumentedBIOS -Class hp_biosEnumeration


########## BIOS / UEFI ##########


########## Regedit registry ##########

# Add Regedit Favorites Registry Keys if not exist
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites'
if (!(Test-Path $regPath)) { New-Item $regPath -Force | Out-Null }

# Another approach, use hash table and oneliner
$RegFavorites = @{'HKLM Run' = 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
$RegFavorites | ForEach-Object { $_.Name; $_.Value }

New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name 'HKLM Run' -Value 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -PropertyType 'String' -Force

# Add HKLM Run Registry path to Regedit Favorites
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name 'HKLM Run' -Value 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -PropertyType 'String' -Force

# Add HKLM RunOnce Registry path to Regedit Favorites
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name 'HKLM RunOnce' -Value 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -PropertyType 'String' -Force

# Add PendingFileNameOperations Registry path to Regedit Favorites
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name 'PendingFileRenameOperations' -Value 'Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' -PropertyType 'String' -Force

# Add Windows Update Reboot Penging to Regedit Favorites
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name 'Windows Update Reboot Pending' -Value 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -PropertyType 'String' -Force

# Add Windows Update Component based Servicing Reboot Pending to Regedit Favorites
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name 'Windows Update Component Based Servicing Reboot Pending' -Value 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -PropertyType 'String' -Force

# Add Networking IPv6 Parameters to Regedit Favorites
$name = 'IPv6 Parameters'
$regPath = 'Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name $Name -Value $regPath -PropertyType 'String' -Force

# Add HKLM Autologon to Regedit Favorites
$name = 'HKLM Autologon - WinLogon'
$regPath = 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites' -Name $Name -Value $regPath -PropertyType 'String' -Force


# Add HKLM Run registry entry
$name = 'Start My Program'
$value = 'C:\ProgramData\MyProgram\foobar.bat'
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty $regPath -Name $Name -Value $value -PropertyType 'ExpandString' -Force


#### Find Image File Execution registry entries ####

$ImageFileExucutionDebuggers = Get-ChildItem 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object { $_ | Where-Object { $_.Property -eq 'Debugger' } }

# Do something if we found Debugger registry keys
if ($ImageFileExucutionDebuggers) {
    Write-Host "There are ImageFileExuction Debugger properties!`n"

    foreach ($Debugger in $ImageFileExucutionDebuggers) {
        $SoftwareName = $Debugger.Name
        $DebuggerValue = $Debugger | ForEach-Object { (Get-ItemProperty "$($_.PSParentPath)`\$($_.PSChildName)").Debugger }

        Write-Host "Software name: $SoftwareName`nValue: $DebuggerValue`n"
    }
	
    #Exit 1
	
}
else {
    # We did not find Image File Execution values from registry
    Write-Output "Did not find ImageFileExecution Debugger registry entries"
    #Exit 0
}

#### Find Image File Execution registry entries ####


########## Regedit ##########

#region Custom object

$properties = @{
    VMName = 'VM01'
    OS     = 'Windows 10'
    Admin  = 'SuperHero'
}
	
$CustomObject = New-Object -TypeName PSObject -Prop $properties
$CustomObject
	
######################################

$CustomObject = New-Object -TypeName psobject 
$CustomObject | Add-Member -MemberType NoteProperty -Name VMName -Value 'VM01'
$CustomObject | Add-Member -MemberType NoteProperty -Name OS -Value 'Windows 10'
$CustomObject | Add-Member -MemberType NoteProperty -Name Admin -Value 'SuperHero'
$CustomObject

######################################
	
$CustomObjects = @()
1..9 | ForEach-Object {

    $properties = @{
        VMName = "VM$_"
        OS     = 'Windows 10'
        Admin  = 'SuperHero'
    }

    $CustomObjects += New-Object -TypeName PSObject -Prop $properties
}	

$CustomObjects
$CustomObjects | Out-GridView

######################################


#endregion Custom object


########## clip Set-Clipboard Get-Clipboard ##########

# List all cab-files and copy names to clipboard so you can paste it to somewhere else
# We use -Expandproperty so we get filenames only without header and we really get only propertyvalue (Set-Clipboard accepts objects)
Get-ChildItem *.cab | Select-Object -Expandproperty Name | Set-Clipboard

# Legacy version using clip.exe
# We use -Expandproperty so we get filenames only without header information
Get-ChildItem *.cab | Select-Object -Expandproperty Name | clip.exe

########## clip Set-Clipboard Get-Clipboard ##########


########## Secure string - get-credential ##########

Get-Credential
$UserCredentials = Get-Credential


# Show password as clear text
$($UserCredentials.GetNetworkCredential().password)

#####

# Change Administrator password here
$PlainPassword = "Password1234!?"

# Encryption key. Use whatever string you want but make sure it IS exactly 16 characters
# This is configured on script or passed as parameter so we can decrypt password and use it with commands
$keyString = "1234567890123456"
$enc = [system.Text.Encoding]::Unicode

$keyStringBytes = $enc.GetBytes($keyString)
$Password = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
$encryptedPassword = $Password | ConvertFrom-SecureString -key $keyStringBytes

Write-Output "Encrypted password: $encryptedPassword"
#Write-Output "Encrypted password was also written to file: $PSScriptRoot\password.txt"
#$encryptedPassword | Out-File "$PSScriptRoot\enrypted_password.txt"

# Convert password back to clear text for debugging/testing
$decryptedPassword = $encryptedPassword | ConvertTo-SecureString -Key $keyStringBytes

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptedPassword)
$decryptedPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

Write-Output ""
Write-Output "Enrypted password decrypted to clear text: $decryptedPassword"

#####

# Ask password with Read-Host
$Password = Read-Host -AsSecureString

# Credentials with empty password
$Credentials = New-Object System.Management.Automation.PSCredential ($UserName, (New-Object System.Security.SecureString))

########## Secure string - get-credential ##########


########## Date time timespan clock ##########

# Get date for example log file names
# This returns: 20181204
(Get-Date).ToString("yyyyMMdd")

$DateTime = Get-Date -Format "yyyyMMddHHmmss"


# Time difference
New-TimeSpan 9:21 17:10


########## Get-Date ##########





########## Windows Hotfix Update ##########

# Show installed hotfix IDs and Date
Get-HotFix | Select-Object HotFixID, InstalledOn

# Show installed hotfix IDs, InstallDate and Date (InstallDate is often empty)
Get-HotFix | Select-Object HotFixID, InstallDate, InstalledOn

# Search hotfixes installed on certain date
Get-HotFix | Where-Object { $_.InstalledOn -like (Get-Date '8.5.2018') }
Get-HotFix | Where-Object { $_.InstalledOn -like (Get-Date '5/8/2018') }

# Search hotfixes installed after certain date (-ge = greater than or equal)
Get-HotFix | Where-Object { $_.InstalledOn -ge (Get-Date '8.5.2018') }

# Search hotfixes installed before certain date (-lt = less than or equal)
Get-HotFix | Where-Object { $_.InstalledOn -le (Get-Date '8.5.2018') }

# Search hotfixes installed in last X days (change number)
Get-HotFix | Where-Object { $_.InstalledOn -ge (Get-Date).AddDays(-10) }

# Installed updates in last 10 days
Get-HotFix | Where-Object { $_.InstalledOn -gt $(Get-Date).AddDays(-10) -and $_.Description -eq "Update" }


# Check InstalledOn format and notice it is in datetime-format
Get-HotFix | Get-Member | Format-List *
Get-HotFix | Get-Member | Where-Object { $_.Name -eq 'InstalledOn' } | Format-List *

# Show last three installed hotfixe
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3


# Get WindowsUpdate Event logs (all IDs), specify how old updates to get as days
$Date = (Get-Date).AddDays(-10)
$Events = Get-WinEvent -FilterHashTable @{ LogName = "Microsoft-Windows-WindowsUpdateClient/Operational"; StartTime = $Date }
$Events

# Show Eventlog event details
$Events | Format-List -Property *


########## Windows Hotfix Update ##########


########## Get-WinEvent start ##########

# Scheduled Tasks Event Logs
$yesterday = (Get-Date) - (New-TimeSpan -day 1)
#$events = get-winevent -FilterHashtable @{logname = "Microsoft-Windows-TaskScheduler/Operational"; level = "2"; StartTime = $yesterday}
$events = Get-WinEvent -FilterHashtable @{logname = "Microsoft-Windows-TaskScheduler/Operational" }
$events | ForEach-Object { $_ }


# Windows Update Event Logs
$Date = (Get-Date).AddDays(-10)
$Events = Get-WinEvent -FilterHashTable @{ LogName = "Microsoft-Windows-WindowsUpdateClient/Operational"; StartTime = $Date }
$Events

########## Get-WinEvent end ##########

########## Scheduled Tasks ##########

# Get Scheduled Task
Get-ScheduledTask -TaskName 'Automatic-Device-Join'
Get-ScheduledTask -TaskName 'Automatic-Device-Join' | Format-List *

# Get Scheduled Task Action
(Get-ScheduledTask -TaskName 'Automatic-Device-Join').CimInstanceProperties
((Get-ScheduledTask -TaskName 'Automatic-Device-Join').CimInstanceProperties).Actions
((Get-ScheduledTask -TaskName 'Automatic-Device-Join').CimInstanceProperties) | Where-Object { $_.Name -eq 'Actions' }
(((Get-ScheduledTask -TaskName 'Automatic-Device-Join').CimInstanceProperties) | Where-Object { $_.Name -eq 'Actions' }).Value

########## Scheduled Tasks ##########


#######################################################################
# Bitlocker

# Suspend Bitlocker forever (because RebootCount is 0)
Suspend-BitLocker -MountPoint "C:" -RebootCount 0

# Suspend Bitlocker until next restart
Suspend-BitLocker -MountPoint "$env:SystemDrive"

# Resume Bitlocker on SystemDrive
Resume-BitLocker -MountPoint "$env:SystemDrive"

# Resume protection for all volumes on a computer
Get-BitLockerVolume | Resume-BitLocker

# Get Bitlocker status on C-drive
Get-BitLockerVolume -MountPoint "$env:SystemDrive"


$BitlockerKeyProtectorID = ((Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).KeyProtectorId
$BitlockerRecoveryKey = ((Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).RecoveryPassword

# $BitlockerRecoveryKey
# | Select -ExpandProperty to remove parenthesis () and our command (pipeline) is also readable. Value is printed without headers
(Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -ExpandProperty RecoveryPassword

# Backup Bitlocker Recovery Key to AD
$BitlockerKeyProtectorID = Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -ExpandProperty KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -ExpandProperty KeyProtectorId
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId "$BitlockerKeyProtectorID"

# Set Bitlocker PIN to Task Sequence -variable
$BDEPin = $tsenv.Value("BDEPin")

####################

# Get AD-object related "sub-objects". In this case Bitlocker Recovery Key
# Thanks Aapeli ;)
$ComputerAccount = 'client01'
$sb = Get-ADComputer $ComputerAccount | Select-Object -ExpandProperty distinguishedname
 
Get-ADObject -Filter * -SearchBase $sb
Get-ADObject -Filter * -SearchBase $sb | Format-List *
Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $sb
Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $sb | Remove-ADObject -WhatIf

####################


#######################################################################
# Hyper-V VM


Get-VM 'Windows10 1803'
$vm = Get-VM 'Windows10 1803'

Start-VM 'Windows10 1803'
Get-VM 'Windows10 1803' | Start-VM

$vm = 'Windows10 1803'
Restart-VM $vm

$vm = 'Windows10 1803'
Start-VM $vm

# Set Gen2-vm first boot option to network boot
$vmname = 'Windows10 1803'
$vm = Get-VM $vmname
$vmswitch = Get-VMNetworkAdapter $vm
Set-VMFirmware $vm -FirstBootDevice $vmswitch

# Set Gen2-vm first boot option to DVD
$vmname = 'Windows10 1803'
$vm = Get-VM $vmname
$dvd = Get-VMDvdDrive $vm
Set-VMFirmware $vm -FirstBootDevice $dvd


$VirtualSwitch = Get-VMSwitch 'Virtual Switch'

# Change VMs virtual switch (vmswitch)
$vmname = 'Client02'
$VMSwitchName = 'Internal Virtual Switch'
$VMSwitchName = 'Virtual Switch'
Get-VM $vmname | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VMSwitchName

# Remove VM's network
Get-HnsNetwork | Where-Object Name -like 'Default Switch' | Remove-HnsNetwork

# Remove VM's VMSwitch
Get-VMSwitch 'Default Switch' | Remove-VMSwitch

# Change selected VMs network to selected network using GUI (Out-GridView)
$vmswitch = Get-VMSwitch | Out-GridView -Title "Select Network to change for VM(s)" -OutputMode Single
Get-VM | Out-GridView -Title "Select VM(s) for network change" -passthru | ForEach-Object { Get-VM $_.Name | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VMSwitch.Name }

# Start selected VMs - Out-GridView
Get-VM | Out-GridView -Title "Select VM(s) for start" -passthru | ForEach-Object { Start-VM $_ }


# Set Gen2-vm first boot option to DVD - Out-GridView - single computer
$vm = Get-VM | Where-Object { $_.VirtualMachineSubType -eq "Generation2" } | Out-GridView -Title "Select VM to boot from DVD" -passthru ; $dvd = Get-VMDvdDrive $vm; Set-VMFirmware $vm -FirstBootDevice $dvd

# Set Gen2-vm first boot option to DVD - Out-GridView - Out-GridView - Multiple computer
$vm = Get-VM | Where-Object { $_.VirtualMachineSubType -eq "Generation2" } | Out-GridView -Title "Select VM to boot from DVD" -passthru | ForEach-Object { $dvd = Get-VMDvdDrive $_.Name; Set-VMFirmware $_.Name -FirstBootDevice $dvd }

# Set Gen2-vm first boot option to Network Boot - Out-GridView - single computer
$vm = Get-VM | Where-Object { $_.VirtualMachineSubType -eq "Generation2" } | Out-GridView -Title "Select VM to boot from Network" -passthru; $vmswitch = Get-VMNetworkAdapter $vm; Set-VMFirmware $vm -FirstBootDevice $vmswitch

# Set Gen2-vm first boot option to Network Boot - Out-GridView - Multiple computers
Get-VM | Where-Object { $_.VirtualMachineSubType -eq "Generation2" } | Out-GridView -Title "Select VM(s) to boot from Network" -passthru | ForEach-Object { $vmswitch = Get-VMNetworkAdapter $_.Name; Set-VMFirmware $_.Name -FirstBootDevice $vmswitch }


# Hyper-V new features 1803 ->
# https://www.thomasmaurer.ch/2017/09/10-hidden-hyper-v-features-you-should-know-about/


# Powershell Direct. New feature 1803 ->
# Manage VM from host computer Powershell. Does not use network connection
Enter-PSSession -VMName "VM01" -Credential (Get-Credential)

# To enable the Virtualization Extensions on the vCPU you can run the following PowerShell command

# Needed when we use Nested Hyper-V VMs
Set-VMProcessor -VMName "VMName" -ExposeVirtualizationExtensions $true

#Enable Virtual TPM chip
Enable-VMTPM -VMName W10-01


# To measure the virtual machine, you can used the following command
Enable-VMResourceMetering -VMName WS2016DX
Measure-VM -VMName WS2016DX

# Export VM
Export-VM -Name TomsVM -Path D:\

# Hyper-V VMSwitch
Get-VMSwitch


# Hyper-V NAT

# To enable you can first create an internal switch using PowerShell,
# the the IP Address on the Virtual NIC on the Management OS and then set the NAT configuration:
#
# This should work - not tested though
New-VMSwitch –SwitchName "NATSwitch" –SwitchType Internal
New-NetIPAddress –IPAddress 172.21.21.1 -PrefixLength 24 -InterfaceAlias "vEthernet (NATSwitch)"
New-NetIPAddress –IPAddress 172.21.21.1 -PrefixLength 24 -InterfaceAlias "vEthernet (NATSwitch)"

# To create NAT forwarding rules you can for example use the following command:
Add-NetNatStaticMapping -NatName “VMSwitchNat” -Protocol TCP -ExternalIPAddress 0.0.0.0 


#######################################################################

# Data Deduplication

# Get status
Get-DedupStatus -Volume "F:"

$dedupVolume = "F:"
#Set-DedupVolume -Volume $dedupVolume -MinimumFileAgeDays 0
 
Write-Output "Starting Dedup Jobs..."
$j = Start-DedupJob -Type Optimization -Volume $dedupVolume
$j = Start-DedupJob -Type GarbageCollection -Volume $dedupVolume
$j = Start-DedupJob -Type Scrubbing -Volume $dedupVolume
 
do {
    Write-Output "Them Dedup jobs is running.  Status:"
    $state = Get-DedupJob | Sort-Object StartTime -Descending 
    $state | Format-Table
    if ($state -eq $null) { Write-Output "Completing, please wait..." }
    Start-Sleep -s 5
} while ($state -ne $null)
 
#clear
Write-Output "Done DeDuping"
Get-DedupStatus | Format-List 

#######################################################################

# Network, adapter, ethernet, ipv4, ipv6


#'vEthernet (Default Switch)'

# Good story about disabling Ipv6 https://www.tenforums.com/tutorials/90033-enable-disable-ipv6-windows.html

# List all Adapter Bindings on network adapter
Get-NetAdapterBinding -Name 'vEthernet (Default Switch)'

# Get all Network adapters with Ipv6 enabled
Get-NetAdapterBinding -ComponentID ms_tcpip6

# Get named network adapter Ipv6 binding
Get-NetAdapterBinding -Name 'vEthernet (Default Switch)' -ComponentID ms_tcpip6

# Get named network adapter Ipv6 binding - show all parameters
Get-NetAdapterBinding -Name 'vEthernet (Default Switch)' -ComponentID ms_tcpip6 | Format-List *

# Get named network adapter Ipv6 binding enabled/disabled
(Get-NetAdapterBinding -Name 'vEthernet (Default Switch)' -ComponentID ms_tcpip6).Enabled

# Get all adapters and Ipv6 enabled state
Get-NetAdapterBinding -ComponentID ms_tcpip6 | Select-Object Name, Enabled, DisplayName

# Disable Ipv6 binding on named network adapter
Disable-NetAdapterBinding -Name "Adapter Name" -ComponentID ms_tcpip6

# Enable Ipv6 binding on named network adapter
Enable-NetAdapterBinding -Name 'vEthernet (Default Switch)' -ComponentID ms_tcpip6


# Disable Ipv6 binding on named network adapter
Disable-NetAdapterBinding -Name 'vEthernet (Default Switch)' -ComponentID ms_tcpip6

# Disable Ipv6 binding on all physical WLAN-adapters
Get-NetAdapter -Physical | Where-Object { $_.InterfaceType -eq 71 } | ForEach-Object { Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 }

#region regexp
################################# Regexp. Fun staff starts here :) ######################################

# Learn and test your regexps with this website
#
#           https://regex101.com/
#

# Basic example

$regex = '^(.*)([0-9]{3})(bar)$'
$string = 'foo123bar'
$string -match $regex

$Matches
$Matches[1]


###

# Greedy vs. lazy regex

# Greedy - no question mark. This will not stop on first </td> because there is another one later
$string = '<tr><td>foo</td><td>bar</td></tr>'
$regex = '^(<tr>)(.*)<\/td>.*$'

# Lazy - question mark stops as soon as it finds first </td>
$string = '<tr><td>foo</td><td>bar</td></tr>'
$regex = ^(<tr>)(.*?)<\/td>.*$




################################# Regexp ######################################
#endregion regexp

#region Import export xml json csv

$vm = Get-VM | Where-Object { $_.Name -eq 'client01' }

#Export object for later analysis
$vm | Export-Clixml -Path ./vm.xml

#Import from XML file
$vm_from_xml = Import-Clixml -Path .\vm.xml


#Export JSON / file
$vm_json = $vm | ConvertTo-Json
$vm_json | Out-File -FilePath ./vm_json.json

#Import JSON from file
# Read file as a whole - multi-line string
$vm_from_imported_json = Get-Content -Raw -Path .\vm_json.json | ConvertFrom-Json


#endregion Import export xml json csv

#######################################################################

# Display friendly file sizes in PowerShell
# https://blogs.technet.microsoft.com/pstips/2017/05/20/display-friendly-file-sizes-in-powershell/




#######################################################################


# Invoke-WebRequest
# wget
# curl

# Download psexec.exe
Invoke-WebRequest -uri https://live.sysinternals.com/psexec.exe -OutFile .\psexec.exe

#######################################################################

# Active Directory 

# Change user attributes

# Set computer where user can log in
$user = get-aduser username -property *
$user.userWorkstations = 'client01,client02,client03'
Set-ADUser -Instance $User

################

# Get AD-object related "sub-objects". In this case Bitlocker Recovery Key
# Thanks Aapeli ;)
$ComputerAccount = 'client01'
$sb = Get-ADComputer $ComputerAccount | Select-Object -ExpandProperty distinguishedname
 
Get-ADObject -Filter * -SearchBase $sb
Get-ADObject -Filter * -SearchBase $sb | Format-List *
Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $sb
Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $sb | Remove-ADObject -WhatIf

################

#######################################################################

# Petri's custom Cloud Managed USB-drive related tests. Regexp with Select-String

# Check if ts.xml -files has certain string. Get all files from subfolders.
Get-ChildItem -file -recurse -filter ts.xml | ForEach-Object { Select-String 'Variable">InstallTeamsOnSharedDevice' $_.FullName }
Get-ChildItem -file -recurse -filter ts.xml | ForEach-Object { Select-String '<variable name="Variable">InstallTeamsOnPersonalDevice</variable>' $_.FullName }

#######################################################################

# Misc staff

# Create unique GUID
New-Guid
(New-Guid).Guid

# Create unique GUID
[guid]::newguid()

# Create unique GUID - Uppercase
(([guid]::newguid()).ToString()).ToUpper()

#########
# Get AUMID

# Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge

$installedapps = Get-AppxPackage

$aumidList = @()
foreach ($app in $installedapps) {
    foreach ($id in (Get-AppxPackageManifest $app).package.applications.application.id) {
        $aumidList += $app.packagefamilyname + "!" + $id
    }
}

$aumidList | Sort-Object
#########

# Activate and show program/process Window foreground
# There can be several iexplore processes. "Hidden" process does not have MainWindowTitle and even can NOT activate that window
$ProcessName = 'iexplore'
(New-Object -ComObject WScript.Shell).AppActivate((Get-Process $ProcessName | Where-Object { $_.MainWindowTitle -ne '' }).MainWindowTitle)

# Activate and show program/process Window
# There can be several iexplore processes. "Hidden" process does not have MainWindowTitle and even can NOT activate that window
# With 15 seconds sleep
powershell.exe -command "& { Start-Sleep -Seconds 15; $ProcessName = 'iexplore'; (New-Object -ComObject WScript.Shell).AppActivate((get-process $ProcessName | Where { $_.MainWindowTitle -ne ''}).MainWindowTitle) }"

# Without 15 seconds sleep (specify 30 seconds wait on Task Scheduler)
powershell.exe -command "& { $ProcessName = 'iexplore'; (New-Object -ComObject WScript.Shell).AppActivate((get-process $ProcessName | Where { $_.MainWindowTitle -ne ''}).MainWindowTitle) }"

###
function Show-Process($Process, [Switch]$Maximize) {
    $sig = '
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern int SetForegroundWindow(IntPtr hwnd);
  '
  
    if ($Maximize) { $Mode = 3 } else { $Mode = 4 }
    $type = Add-Type -MemberDefinition $sig -Name WindowAPI -PassThru
    $hwnd = $process.MainWindowHandle
    $null = $type::ShowWindowAsync($hwnd, $Mode)
    $null = $type::SetForegroundWindow($hwnd) 
}

$ProcessName = 'iexplore'
$Process = Get-Process $ProcessName | Where-Object { $_.MainWindowTitle -ne '' }
Show-Process -Process $Process

###


#########

function Test-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

# If user is NOT Administrator
if (-not (Test-Administrator)) {
    Write-Host "This software needs to be run As Administrator"
    Exit 0
}



# Batch-version

@echo off

Write-Output Checking if you have Administrator permissions...

net.exe session >nul 2>&1
if %errorLevel% == 0 (
    Write-Output You have Administrator permissions, starting installer...
    pushd "%~dp0"
    powershell.exe -Command "& {Start-Process PowerShell.exe -ArgumentList '-NonInteractive -NoProfile -ExecutionPolicy Bypass -File Files\InstallMinecraft.ps1' -Verb RunAs}"
    Write-Output Installation Complete
    exit
) else (
    Write-Output Failure: Administrator permission is required to install. Please right click InstallMinecraftEducationEdition.bat and Select Run as Administrator... 
)

Pause >nul

#########


#######################################################################

# SCCM, ConfigMgr

# Load SCCM/ConfigMgr Powershell-module (put these lines to your Powershell-profile)
Import-Module 'E:\Program Files\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
Set-Location YOD:

# Load SCCM/ConfigMgr Powershell-module
# Not tested yet but should work
$SCCMSitePath = "<SITECODE>"
Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)
#Set current directory to SCCM site
Set-Location -Path $SCCMSitePath

##### Device #####

# SCCM/ConfigMgr find device
Get-CMDevice -Name client02

# ResourceId
$ResourceId = (Get-CMDevice -Name "ComputerName").ResourceID

# SCCM/ConfigMgr Remove device
Get-CMDevice -Name client02 | Remove-CMDevice

# SCCM/ConfigMgr Remove device without questions
Get-CMDevice -Name client02 | Remove-CMDevice -Force


##### Collection #####

# Add computer to SCCM/ConfigMgr collection in different ways
Add-CMDeviceCollectionDirectMembershipRule -CollectionName  "Collection_name" -ResourceId $(Get-CMDevice -Name "ComputerName").ResourceID
Add-CMDeviceCollectionDirectMembershipRule -CollectionName  $CollectionName -ResourceId $(Get-CMDevice -Name $ComputerName).ResourceID
Add-CMDeviceCollectionDirectMembershipRule -CollectionID $CollectionID -ResourceId $(Get-CMDevice -Name $ComputerName).ResourceID
Get-CMDeviceCollection -name "Windows 10 1709.1 Upgrade TS" | Add-CMDeviceCollectionDirectMembershipRule -ResourceId (Get-CMDevice -Name "ComputerName").ResourceID

# Get list of computer names from text file and add them to collection
#
# Notice that this approach have problems after 500 devices. Use Device object instead of resourceId
#
# I will update these examples later
#
Get-Content "C:\temp\computers.txt" | ForEach-Object { Add-CMDeviceCollectionDirectMembershipRule -CollectionID "YOD0001A" -ResourceID (Get-CMDevice -Name $_).ResourceID }
Get-Content "C:\temp\computers.txt" | ForEach-Object { Add-CMDeviceCollectionDirectMembershipRule -CollectionName  $CollectionName -ResourceID (Get-CMDevice -Name $_).ResourceID }

##### Packages, Programs #####

# Find package by id
Get-CMPackage -Id "YOD00007"

# Find package by name
Get-CMPackage -Name "Configuration Manager Client Piloting Package"

# Find program by packageid
Get-CMProgram -PackageId "YOD0003C"

# Find program by PackageName
Get-CMProgram -PackageName 'Foobar'

# Find program by ProgramName
Get-CMProgram -ProgramName "Setup"

# Find Deployment by DeploymentId
Get-CMDeployment -DeploymentId 'YOD20023'

# Find Deployment by ProgramName
Get-CMDeployment -ProgramName 'Copy Windows Performance Toolkit files'

# Find Deployment by SoftwareName
Get-CMDeployment -SoftwareName 'Copy Windows Performance Toolkit files (Copy Windows Performance Toolkit files)'

# Find Deployment by CollectionName
Get-CMDeployment -CollectionName 'Troubleshooting users'


# Check if SCCM client is in provisioning mode
# https://garytown.com/configmgr-client-provisioning-mode

# Check if ProvisioningMode is true/false
Get-ItemProperty -Path HKLM:\Software\Microsoft\CCM\CcmExec -Name "ProvisioningMode"

# Does not work on Powershell 3.0 or earlier
Get-ItemPropertyValue -Path HKLM:\Software\Microsoft\CCM\CcmExec -Name "ProvisioningMode"
# Workaround
(Get-ItemProperty -Path HKLM:\Software\Microsoft\CCM\CcmExec -Name "ProvisioningMode").ProvisioningMode

Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client"

# Exit SCCM Client Provisioning mode
#PowerShell:
Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "SetClientProvisioningMode" $false

#CommandLine:
WMIC.exe /namespace:\\root\ccm path sms_client CALL SetClientProvisioningMode "False" /NOINTERACTIVE


# Find Package by Id
# https://docs.microsoft.com/en-us/powershell/module/configurationmanager/get-cmpackage?view=sccm-ps
Get-CMPackage -Id "packageId"

# Find Deployment by Id
# https://docs.microsoft.com/en-us/powershell/module/configurationmanager/get-cmdeployment?view=sccm-ps
Get-CMDeployment -DeploymentId "DeploymentId"


# SCCM check reboot pending. Good article how look from SCCM WMI
#WMI / Powershell and the Configuration Manager Client
#https://blogs.technet.microsoft.com/configmgrdogs/2014/09/03/wmi-powershell-and-the-configuration-manager-client/


#######################################################################

#Delete specific user profile by path
(Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\test55" }).Delete()


# Show Windows 10 user profiles in Out-GridView and delete selected profiles
$UserLocalPaths = Get-WmiObject -Class Win32_UserProfile | Select-Object LocalPath | Sort-Object LocalPath | Out-GridView -title "Delete user profile" -Passthru;
foreach ($UserLocalPath in $UserLocalPaths) {
    (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq "$($UserLocalPath.LocalPath)" }).Delete();
    
    if ($?) { Write-Output "Deleted user profile $($UserLocalPath.LocalPath)" } else { Write-Output "Error could NOT delete user profile! $($UserLocalPath.LocalPath)" }
}


# Remove all not-loaded profiles
# Get-WmiObject -Class Win32_UserProfile -filter "Loaded=FALSE" |foreach {$_.Delete()}


#######
# Get user Profiles older than X day and show graphical Out-GridView and delete selected user profiles

# Get profile folders from C:\Users\
$DaysOldUserProfiles = 1
$UserLocalPaths = Get-ChildItem -Directory C:\Users | Where-Object { $_.LastWriteTime -le ((Get-Date).AddDays(-$DaysOldUserProfiles)) } | Select-Object FullName | Sort-Object FullName | Out-GridView -title "Delete user profile older than $DaysOldUserProfiles days"

# Delete selected user profiles
foreach ($UserLocalPath in $UserLocalPaths) {
    (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq "$($UserLocalPath.LocalPath)" }).Delete()
   
    if ($?) { Write-Output "Deleted user profile $($UserLocalPath.LocalPath)" } else { Write-Output "Error could NOT delete user profile! $($UserLocalPath.LocalPath)" }
}
#######


#######################################################################

# Powershell Internet Explorer

# Control IE with Powershell good article
# https://www.gngrninja.com/script-ninja/2016/9/25/powershell-getting-started-controlling-internet-explorer

$ieObject = New-Object -ComObject 'InternetExplorer.Application'

https://gallery.technet.microsoft.com/scriptcenter/Create-or-close-tabs-in-cc6a4e39


#######################################################################

# Set Application Windows to Focus and Top
function Show-Process($Process, [Switch]$Maximize) {
    $sig = '
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern int SetForegroundWindow(IntPtr hwnd);
  '
  
    if ($Maximize) { $Mode = 3 } else { $Mode = 4 }

    # Force Maximize
    #$Mode = 3


    $type = Add-Type -MemberDefinition $sig -Name WindowAPI -PassThru
    $hwnd = $process.MainWindowHandle
    $null = $type::ShowWindowAsync($hwnd, $Mode)
    $null = $type::SetForegroundWindow($hwnd) 
}

$ieProc = Get-Process | Where-Object { $_.MainWindowHandle -eq $ie.HWND }
Show-Process $ieProc -Maximize

#######################################################################

# Returns how many full days since last Reboot
#
# This can be used as SCCM Configuration Item
#
# Petri.Paavola@yodamiitti.fi
# 16.5.2018

try {
    # Wmi query returns date as String
    $LastBootUpTimeAsString = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime

    # Convert String to DateTime
    $LastBootUpTimeAsDateTime = [Management.ManagementDateTimeConverter]::ToDateTime($LastBootUpTimeAsString)

    $now = Get-Date

    # Calculate difference between now and boottime
    $DaysSinceLastBootTime = ($now - $LastBootUpTimeAsDateTime).Days

    <# Example of values above returns.
    Days              : 1
    Hours             : 9
    Minutes           : 18
    Seconds           : 42
    Milliseconds      : 982
    Ticks             : 1199229821911
    TotalDays         : 1,38799747906366
    TotalHours        : 33,3119394975278
    TotalMinutes      : 1998,71636985167
    TotalSeconds      : 119922,9821911
    TotalMilliseconds : 119922982,1911
    #>

    # We output full days (integer)
    $DaysSinceLastBootTime
}
catch {
    # Do something if we failed
    Exit 1
}

#######################################################################################################################

# Format USB-drive
# This is working, still use at your own risk! Do not run before evaluating what this does!

$LabelName = "USB-drive"

$selectedDiskNumber = 9999
$disk = Get-Disk | Where-Object { $_.BusType -eq "USB" }

$selectedDisk = $disk | Out-GridView -Title "Select USB-drive to format" -PassThru

# Stop if nothing is selected
if (!$selectedDisk) {
    Write-Output "No disk selected, exiting script"
    Exit 1
}

$selectedDiskNumber = $selectedDisk.Number

if (($selectedDiskNumber -eq 0) -or ($selectedDiskNumber -eq 1)) {
    Write-Output "Trying to use internals disks. We will exit now!"
    Exit 0
}

# Hardcoded for debugging
#$selectedDiskNumber = 2

Write-Output "Selected disk number: $selectedDiskNumber"

Write-Output "Cleaning partition from diskNumber $selectedDiskNumber ($($selectedDisk.FriendlyName))"
Clear-Disk -Number $selectedDiskNumber -RemoveData

Write-Output "Creating partition"

$partitionInfo = New-Partition -DiskNumber $selectedDiskNumber -MbrType "FAT32" -IsActive -UseMaximumSize -AssignDriveLetter
$partitionInfo

$DriveLetter = $partitionInfo.DriveLetter
$DriveLetterWithColon = $DriveLetter + ":"

Write-Output "Format USB-drive from drive letter: $DriveLetter"
Format-Volume -DriveLetter $DriveLetter


Write-Output "Changing drive $DriveLetterWithColon label to $LabelName"
$drive = Get-WmiObject "Win32_LogicalDisk WHERE DeviceID='$($DriveLetterWithColon)'"
$drive.VolumeName = $LabelName
$null = $drive.Put()

#######################################################################

# Windows "shortcuts"

# Local Users and Groups
lusrmgr.msc

# Computer Management
compmgmt.msc

# Disk Management
diskmgmt.msc

# Event viewer
eventvwr.msc

# Scheduled Tasks
taskschd.msc

# Network adapters
ncpa.cpl

# System Properties
sysdm.cpl

# Programs and features
appwiz.cpl


#######################################################################

function Create_Local_Useraccount {
    Param(
        [String] $Username,
        [String] $UserPasswordPlainText
    )

    $UserPasswordSecureString = ConvertTo-SecureString $UserPasswordPlainText -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($UserName, $UserPasswordSecureString)

    #########

    # Create user account

    # User does not belong to any group after this command
    # User may not even log in to computer before we add at least Users-group membership

    # We can go wrong with this because original Command Prompt command: net user username password /ADD
    # automatically adds user to Users-group

    New-LocalUser -AccountNeverExpires -Name $UserName -Password $UserPasswordSecureString -PasswordNeverExpires

    #########

    # Add user to Users-group. We are using Well-Known SID for Users-group so this will work in any language Windows
    # Name: Users
    # SID: S-1-5-32-545
    
    $UsersGroupName = Get-WmiObject win32_group -filter "LocalAccount = $TRUE And SID = 'S-1-5-32-545'" | Select-Object -expand name
    Add-LocalGroupMember -Group $UsersGroupName -Member $Username

    # Add user to local Administrators group
    #$AdminGroupName = gwmi win32_group -filter "LocalAccount = $TRUE And SID = 'S-1-5-32-544'" | select -expand name
    #Add-LocalGroupMember -Group $AdminGroupName -Member $Username

    # Disable password requirement. Why would we do something like this ?-)
    #&net user $UserName /passwordreq:no

    # Make sure user needs to have password. Should be default value
    & net.exe user $UserName /passwordreq:yes

}

Create_Local_Useraccount 'UserName' 'Password'

#######################################################################

# Windows 10 Feature On Demand FOD

# https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities
# https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod


# We can manage these with native Powershell Cmdlets or with DISM

Get-WindowsCapability -Online
Add-WindowsCapability -Online -Name 'NetFX3~~~~'


##### .NetFramework3 #####

# Check .NetFramework3 is installed
#Name  : NetFX3~~~~
#State : NotPresent

# Get .NetFrameWork3
Get-WindowsCapability -Online | Where-Object { $_.Name -eq "NetFX3~~~~" }

# Get .NetFrameWork3
(Get-WindowsCapability -Online | Where-Object { $_.Name -eq "NetFX3~~~~" }).State

# Install .NetFrameWork3 if it is not installed
$Capability = 'NetFX3~~~~'
if (((Get-WindowsCapability -Online | Where-Object { $_.Name -eq $Capability }).State) -eq 'NotPresent') {
    Write-Output "Install Feature on Demand Package: $Capability"
    $Return = Add-WindowsCapability -Online -Name $Capability

    if ($Return.RestartNeeded -eq $True) {
        Write-Output "Computer needs to be restarted to finish installation"
    }
}

# Command above should return to our console something like this
Path          :
Online        : True
RestartNeeded : False



##### .NetFramework3 #####

# List Finnish language packs
Get-WindowsCapability -Online | Where-Object { $_.Name -like "*fi-FI*" }

# Install Finnish language packs
Get-WindowsCapability -Online | Where-Object { $_.Name -like "*fi-FI*" } | ForEach-Object { Write-Output "Installing package: $($_.Name)"; Add-WindowsCapability -Online -Name $_.Name }


################### dism, WinPE, offline, image ###################

# Windows 10 dism/offline image Powershell commands
# https://docs.microsoft.com/en-us/powershell/module/dism/?view=win10-ps

# List Feature On-Demand capabilities
Dism.exe /online /get-capabilities


# List installed FOD-packages
#Capability Identity : Language.OCR~~~de-DE~0.0.1.0
#State : Installed
# We use Select-String to find if FOD is installed and then we return that line and previous line
Dism.exe /online /get-capabilities | Select-String "Installed" -Context 1, 0

# Install FOD-package
Dism.exe /Online /Add-Capability /CapabilityName:Language.Basic~~~en-US~0.0.1.0


# List Finnish language packs
Dism.exe /online /get-capabilities | Where-Object { $_ -like "*fi-FI*" }
<#

PS C:\temp> dism /online /get-capabilities|where {$_ -like "*fi-FI*" }
Capability Identity : Language.Basic~~~fi-FI~0.0.1.0
Capability Identity : Language.Handwriting~~~fi-FI~0.0.1.0
Capability Identity : Language.OCR~~~fi-FI~0.0.1.0
Capability Identity : Language.TextToSpeech~~~fi-FI~0.0.1.0
Capability Identity : Language.UI.Client~~~fi-FI~

#>

# List Finnish language pack exact names
Dism.exe /online /get-capabilities | Where-Object { $_ -like "*fi-FI*" } | ForEach-Object { ($_.Split(" "))[3] }
<#
Language.Basic~~~fi-FI~0.0.1.0
Language.Handwriting~~~fi-FI~0.0.1.0
Language.OCR~~~fi-FI~0.0.1.0
Language.TextToSpeech~~~fi-FI~0.0.1.0
Language.UI.Client~~~fi-FI~
#>

# Install Finnish language pack
# This does NOT work. Name comes wrong with this syntax
#dism /online /get-capabilities|where {$_ -like "*fi-FI*" } | Foreach { DISM.exe /Online /Add-Capability /CapabilityName:(($_.Split(" "))[3]) }

# Works fi-FI
Dism.exe /online /get-capabilities | Where-Object { $_ -like "*fi-FI*" } | ForEach-Object { $PackageName = (($_.Split(" "))[3]); Write-Output "Install: $PackageName"; Dism.exe /Online /Add-Capability /CapabilityName:$PackageName }

# Works de-DE
Dism.exe /online /get-capabilities | Where-Object { $_ -like "*de-DE*" } | ForEach-Object { $PackageName = (($_.Split(" "))[3]); Write-Output "Install: $PackageName"; Dism.exe /Online /Add-Capability /CapabilityName:$PackageName }


# Install drivers to WinPE
Mount-WindowsImage -Path .\mount -ImagePath .\LiteTouchPE_x64.wim -Index 1
Add-WindowsDriver -Path ".\mount" -Driver ".\WinPE_drivers_to_add" -Recurse > ".\driveradd.txt"
Dismount-WindowsImage -Path .\mount -Save


#######################################################################

# Check Windows version or build number (1709, 1803, 16299)

Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID | Select-Object ReleaseID
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId

<#
ReleaseId
-------- -
1709
#>


(Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2).BuildNumber
# 16299

(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild
# 16299

Get-CimInstance Win32_OperatingSystem | Select-Object buildnumber, version
<#
buildnumber version
----------- -------
16299       10.0.16299
#>

# Update build number
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
# 492
# Whole version 10.16299.491




#######################################################################

Try {

}
Catch {
    Write-Error "$($_.Exception.GetType().FullName)"
    Write-Error "$($_.Exception.Message)"
    Write-Error "$($_.Exception.StackTrace)"
    Write-Error "$($_.ScriptStackTrace)"
    Write-Error "$($_.InvocationInfo.PositionMessage)"
    Write-Error "$($_.CategoryInfo)"
    Write-Error "$($_.FullyQualifiedErrorId)"    
}



#######################################################################

# If you actually want each line as a separate object, use (Get-Content ($file)).Split("`n") to split it at the newlines.


#######################################################################

# Speech

# https://mcpmag.com/articles/2018/03/07/talking-through-powershell.aspx

Add-Type -AssemblyName System.speech
$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speak.Speak('Hello...')

$speak.Speak("The current date and time is $(Get-Date)")

$speak.Volume = 100

$speak.Rate = 10
$speak.Speak("The current date and time is $(Get-Date)")

$speak.Rate = -10
$speak.Speak("The current date and time is $(Get-Date)")

$speak.voice

$speak.GetInstalledVoices()
$speak.GetInstalledVoices() | ForEach-Object { $_.VoiceInfo }

# Save to wav file
$speak.SetOutputToWaveFile("$($PWD)\Speech.wav")
$speak.Speak("Hello there!")
Get-Item .\Speech.wav


#######################################################################

# Get Display/screen information

#https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.screen.allscreens?view=netframework-4.7.2#System_Windows_Forms_Screen_AllScreens
$AllScreens = [System.Windows.Forms.Screen]::AllScreens


#######################################################################

# Extract icon from exe
$icon = ([System.Drawing.Icon]::ExtractAssociatedIcon("C:\windows\System32\cmd.exe"))

#######################################################################
# Base64

# Convert images to base64 which are used in WPF scripts

$ImageFilePath = "C:\temp\picture.png"
[convert]::ToBase64String((Get-Content $ImageFilePath -encoding byte)) | Set-Clipboard

#######################################################################
# Configure Windows 10 Default user profile offline (ntuser.dat)

&reg.exe LOAD HKLM\DEFUSER C:\Users\Default\NTUSER.DAT
$regPath = 'HKLM:\DEFUSER\Software\Microsoft\Windows\CurrentVersion\Policies\System'
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty $regPath -Name "WallpaperStyle" -Value "Fill" -PropertyType "String" -Force
New-ItemProperty $regPath -Name "Wallpaper" -Value $LockScreenImage -PropertyType "String" -Force
Log -Message "User desktop background image set. Success: $?" -Component "$($env:computername)" -LogFile $LogFile

$unloaded = 1
$attempts = 0
while (($unloaded -ne 0) -and ($attempts -le 5)) {
    Log -Message "Unloading Default User registry, attempt: $attempts" -Component "$($env:computername)" -LogFile $LogFile
    [gc]::Collect() # necessary call to be able to unload registry hive
    Start-Sleep -Seconds 1
    &reg.exe UNLOAD HKLM\DEFUSER
    $unloaded = $LastExitCode
    $attempts += 1        
}

if ($unloaded -ne 0) {
    Log -Message "Error: Could NOT unload Default User registry. Users may not succeed on logins." -Component "$($env:computername)" -LogFile $LogFile
}

#######################################################################
# Windows Drivers

# Find what device is using inf-driver
Get-WmiObject Win32_pnpsigneddriver | Where-Object { $_.InfName -like 'oem50.inf' }

# Check if there are problems with drivers
# If we get anything then that device have problems with driver
Get-WmiObject Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
Get-WmiObject Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | Select-Object Name, Description, DeviceID, PNPDeviceID, Status

# Add and install Windows drivers from subfolders
& pnputil.exe /add-driver *inf /install /subdirs


#####

# Delete all oem-drivers from computer

# Check that command works, does not remove driver, just shows what command would be run
Get-WMIObject Win32_pnpsigneddriver | where {$_.infname -like 'oem*.inf' } | select infname | foreach { write-host "& pnputilFOO.exe /delete-driver $($_.InfName) /Force" }

# Windows 10 pnputil syntax (new syntax)
Get-WMIObject Win32_pnpsigneddriver | where {$_.infname -like 'oem*.inf' } | select infname | foreach { & pnputil.exe /delete-driver $($_.InfName) /Force }

# Windows 7 pnputil syntax
Get-WMIObject Win32_pnpsigneddriver | where {$_.infname -like 'oem*.inf' } | select infname | foreach { & pnputil.exe -f -d $($_.InfName) }

#####


#######################################################################

# Delete all folder Child-Items (files and directories) but leave folder in place
Remove-Item C:\temp\test\* -Recurse -Force

# Delete all C:\temp\test -folder Child-Items (files and directories) AND delete also C:\temp\test -folder itself
Remove-Item C:\temp\test -Recurse -Force

# Delete subdirectories which start with name sp
Get-ChildItem C:\temp\test -Filter 'sp*' -Directory | Remove-Item  -Recurse -Force

# Remember -WhatIf option. Test what would be deleted
Get-ChildItem C:\temp\test -Filter 'sp*' -Directory | Remove-Item  -Recurse -Force -WhatIf


#######################################################################

# Export Autopilot device hash

Set-ExecutionPolicy bypass -scope Process
mkdir c:\temp
Set-Location c:\temp
Save-Script -Name Get-WindowsAutoPilotInfo -Path 'c:\temp' -RequiredVersion 1.3
.\Get-WindowsAutoPilotInfo.ps1 -OutputFile c:\temp\MyComputers.csv

#######################################################################




