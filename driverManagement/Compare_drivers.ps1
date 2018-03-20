# Compares Device Driver XML-files from 2 computer and tells difference.
# Good for making sure you install right drivers comparing to OEM-installation
#
# This will recognize if DeviceID has different Driver Manufacturer.
# Driver version is allowed to be different if Driver Manufacturer is same.
#
# You can make XML-file on workstation in Powershell with command:
# Get-WmiObject Win32_pnpsigneddriver | Export-CliXml -Path ".\$((Get-WmiObject -Class win32_computersystem).Manufacturer) $((Get-WmiObject -Class win32_computersystem).Model) Win32_pnpsigneddriver.xml"
#
# Use case: install OEM-Windows, update it and export 3rd party drivers with Export_drivers.ps1. Export_drivers.ps1 Script will also make xml file automatically
# Install computer in your environment with your driver package
# After installation compare OEM installation and your production installation Win32_pnpsigneddriver xml-files.
#
# Version 0.9
#
# Petri.Paavola@yodamiitti.fi
# 20.3.2018
#

param (
    [string]$computer1XMLFilePath,
    [string]$computer2XMLFilePath
 )



# Test are there enough parameters (2)
if ($psboundparameters.Count -ne 2) {
    Write-Host "Give parameters to 2 XML-files to compare" 
    Write-Host "You can make XML-file with command:"
    Write-Host 'Get-WmiObject Win32_pnpsigneddriver | Export-CliXml -Path ".\$((Get-WmiObject -Class win32_computersystem).Manufacturer) $((Get-WmiObject -Class win32_computersystem).Model) Win32_pnpsigneddriver.xml"'
    exit 1
}

# Copy file names from arguments
$computer1FileName = split-path $computer1XMLFilePath -Leaf
$computer2FileName = split-path $computer2XMLFilePath -Leaf


function Remove_Device_InstanceID_from_DeviceID {
	<#
    .Synopsis
        Removes Device InstanceID from DeviceID-table in array.
        https://msdn.microsoft.com/en-us/library/windows/hardware/ff541327(v=vs.85).aspx
    .Description
        Remove computer specific information from DeviceID-field (last field)
    .Parameter array
        Array which has DeviceID-table
    #>
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.Collections.ArrayList]$array
    )
  
    process {
        foreach ($item in $array) {
            # Examples
       		# PCI\VEN_8086&DEV_1E22&SUBSYS_18DF103C&REV_04\3&21436425&0&FB
            # ACPI\FIXEDBUTTON\2&DABA3FF&2B
            # https://msdn.microsoft.com/en-us/library/windows/hardware/ff541327(v=vs.85).aspx

            # If DeviceID has 2 backslashes and in last section there is & character then match will return True (If is true)
            # It is important to process only devices which have at least one & character in last section. Otherwise we would remove too much data.
            if($item.DeviceID -match ".*\\*.\\.*&.*") {
                
                # Debug
                #Write-Host $item.DeviceID
                
                # PCI
                $first = ($item.DeviceID -split "\\")[0]

                # VEN_8086&DEV_1E22&SUBSYS_18DF103C&REV_04
                $second = ($item.DeviceID -split "\\")[1]

                # Why this is working :)
                $item.DeviceID = "$($first)\$($second)"
            }
            #$item.DeviceID
        }
        return $array
	}
}

# Create arrays based on XML-files
# Select only necessary attributes
[System.Collections.ArrayList]$computer1 = Import-CliXml $computer1XMLFilePath | Where-object {$_.DeviceClass -ne "LEGACYDRIVER" -and ![string]::IsNullOrEmpty($_.DeviceClass)} | Select-Object DeviceID,DeviceName,DeviceClass,Manufacturer,DriverProviderName,DriverVersion|sort-object DeviceName
[System.Collections.ArrayList]$computer2 = import-CliXml $computer2XMLFilePath | Where-object {$_.DeviceClass -ne "LEGACYDRIVER" -and ![string]::IsNullOrEmpty($_.DeviceClass)} | Select-Object DeviceID,DeviceName,DeviceClass,Manufacturer,DriverProviderName,DriverVersion|sort-object DeviceName


# Cleanup DeviceID, get rid of computer specific unique information from end of the DeviceID
$computer1 = Remove_Device_InstanceID_from_DeviceID($computer1)
$computer2 = Remove_Device_InstanceID_from_DeviceID($computer2)


# Make clone array because in foreach loop we can NOT remove entries on array we are processing
# We will remove common entries in both files. End result are entries which are unique in both computers
# Array needs to be casted as [System.Collections.ArrayList] so we can do Remove to array entries
[System.Collections.ArrayList]$computer1Edit = $computer1.clone()
[System.Collections.ArrayList]$computer2Edit = $computer2.clone()

# This has drivers which have conflict on each files (= are different in each file)
# These are listed last and this is the most important information in this tool
$problemdrivers = New-Object System.Collections.ArrayList

# Change console colour to green on OK devices (which have same manufacturer drivers)
#$HOST.UI.RawUI.BackgroundColor = "DarkBlue"
$HOST.UI.RawUI.ForegroundColor = "Green"


# Run through all DeviceIDs from first computer and try to find same DeviceID on second computer
# If same is found then it is "green", if found only from another (may not be problem), found from both but have different Driver Manufacturer (red alert)
foreach ($driverentry in $computer1) {

    # Find all identical driver files (checking values DeviceID, DriverProviderName, Manufacturer)
    # Compare to $computer2Edit because if there are more than 1 line then take these lines away one at a time from this array
    if ($same = $computer2Edit | where-object {$driverentry.DeviceID -eq $_.DeviceID -and $driverentry.DriverProviderName -eq $_.DriverProviderName -and $driverentry.Manufacturer -eq $_.Manufacturer}) {

        # Some devices can occur several times with exact same information (for example IDE Channel)
        # If above returns several objects if there are more than one.
        # In this case we need to go each as individual objects.
        if ($same.count -ge 2) {

            # we use -f because it can format text better and have 2 columns (instead of Write-Host)
            $spaces = 55 - $same[0].DeviceName.Length
            "{0}{1,$spaces}" -f $same[0].DeviceName, "" + $same[0].DeviceID

            #write-host -ForegroundColor "Green" "SAME: $($same[0].DeviceName)`t`t`t`t$($same[0].DeviceID)"
            $computer1Edit.Remove($driverentry)
            $computer2Edit.Remove($same[0])
        }
        else {
            # We found only 1 Device with same name (normal case)

            # we use -f because it can format text better and have 2 columns (instead of Write-Host)
            $spaces = 55 - $same.DeviceName.Length
            "{0}{1,$spaces}" -f $same.DeviceName, "" + $same.DeviceID
			
            #write-host -ForegroundColor "Green" "SAME: $($same.DeviceName)`t`t`t`t$($same.DeviceID)"
            $computer1Edit.Remove($driverentry)
            $computer2Edit.Remove($same)
        }
    }
    else {
        # Same DeviceID has different driver detail. In this case something is usually wrong!
        
        if ($same = $computer2Edit | where-object {$driverentry.DeviceID -eq $_.DeviceID}) {

            # If found more than 1 driver we need to manage it differently
            if ($same.count -ge 2) {
                Write-Host -Foreground "Red" "Differ ($computer1FileName): $($driverentry.DeviceName)`t$($driverentry.DeviceID)`t$($driverentry.DriverProviderName)`t$($driverentry.Manufacturer)`t$($driverentry.DriverVersion)"
                Write-Host -Foreground "Red" "Differ ($computer2FileName): $($same[0].DeviceName)`t$($same[0].DeviceID)`t$($same[0].DriverProviderName)`t$($same[0].Manufacturer)`t$($same[0].DriverVersion)"

                # Add to problems array which is listed in the end
                $problemdrivers.Add($driverentry) | Out-Null
                $problemdrivers.Add($same[0]) | Out-Null

                $computer1Edit.Remove($driverentry)
                $computer2Edit.Remove($same[0])
            }
            else {
                # Found only 1 conflicting driver (this is normal case)

                Write-Host -Foreground "Red" "Differ ($computer1FileName): $($driverentry.DeviceName)`t$($driverentry.DeviceID)`t$($driverentry.DriverProviderName)`t$($driverentry.Manufacturer)`t$($driverentry.DriverVersion)"
                Write-Host -Foreground "Red" "Differ ($computer2FileName): $($same.DeviceName)`t$($same.DeviceID)`t$($same.DriverProviderName)`t$($same.Manufacturer)`t$($same.DriverVersion)"
            
                $problemdrivers.Add($driverentry) | Out-Null
                $problemdrivers.Add($same) | Out-Null

                $computer1Edit.Remove($driverentry)
                $computer2Edit.Remove($same)
            }
        }
        
    }
}

# Return console colours to normal
#$HOST.UI.RawUI.BackgroundColor = "DarkBlue"
$HOST.UI.RawUI.ForegroundColor = "White"


Write-Host

Write-Host "$($computer1FileName) unique drivers ($($computer1Edit.Count)):"
#$computer1Edit|select DeviceName, DeviceID, Manufacturer, DriverProviderName, DriverVersion|ft

foreach ($driverentry in $computer1Edit) {
    if($driverentry.DriverProviderName -ne "Microsoft") {
        #$HOST.UI.RawUI.BackgroundColor = "DarkBlue"
        $HOST.UI.RawUI.ForegroundColor = "Yellow"
        #$driverentry|select DeviceName, DeviceID, Manufacturer, DriverProviderName, DriverVersion|ft -wrap -hideTableHeaders
        $driverentry|select DeviceName, DeviceID, Manufacturer, DriverProviderName, DriverVersion|fl
        #"{0}{1}{2}{3}{4}" -f $driverentry.DeviceName, ""+$driverentry.DeviceID, ""+$driverentry.Manufacturer, ""+$driverentry.DriverProviderName, ""+$driverentry.DriverVersion
        #"{0}{1,23}{2,30}{3,40}{4,50}" -f $driverentry.DeviceName, $driverentry.DeviceID, $driverentry.Manufacturer, $driverentry.DriverProviderName, $driverentry.DriverVersion
        $HOST.UI.RawUI.ForegroundColor = "White"
        $HOST.UI.RawUI.BackgroundColor = "Black"
    } else {
        #$driverentry|select DeviceName, DeviceID, Manufacturer, DriverProviderName, DriverVersion|ft -wrap -hideTableHeaders
        #"{0}{1}{2}{3}{4}" -f $driverentry.DeviceName, ""+$driverentry.DeviceID, ""+$driverentry.Manufacturer, ""+$driverentry.DriverProviderName, ""+$driverentry.DriverVersion
        "{0}{1}{2}{3}{4}" -f $driverentry.DeviceName, $driverentry.DeviceID, $driverentry.Manufacturer, $driverentry.DriverProviderName, $driverentry.DriverVersion
    }
}

Write-Host "$($computer2FileName) unique drivers ($($computer2Edit.Count)):"
$computer2Edit|select DeviceName, DeviceID, Manufacturer, DriverProviderName, DriverVersion|ft

$HOST.UI.RawUI.ForegroundColor = "Red"
Write-Host "Possible problem drivers!:"
$problemdrivers|select DeviceName, DeviceID, Manufacturer, DriverProviderName, DriverVersion
$HOST.UI.RawUI.ForegroundColor = "White"

