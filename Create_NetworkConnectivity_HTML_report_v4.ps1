# Create HTML report from Network Connectivity test
#
# Petri.Paavola@yodamiitti.fi
# 21.11.2019

$ReportRunDateTime = (Get-Date).ToString("yyyyMMddHHmm")

$head = @'
<style>
    body {
        background-color:#dddddd;
        font-family:Tahoma;
        font-size:12pt;
    }
    td, th {
        border:1px solid black;
        border-collapse:collapse;
    }
    th {
        color:white;
        background-color:black;
    }
    table, tr, td, th {
        padding: 2px; margin: 0px
    }
    table { 
        margin-left:50px;
    }
</style>
'@

$Win32_ComputerSystem = Get-CimInstance Win32_ComputerSystem

# Test network connection
$TestNetConnection = Test-NetConnection -ComputerName 8.8.8.8 -TraceRoute		

# SourceIPAddress
$SourceIPAddress = $TestNetConnection.SourceAddress.IPAddress

# Add SourceIPAddress -property to "main" object
$TestNetConnection | Add-Member NoteProperty 'SourceIPAddress' $SourceIPAddress


# RoundTripTime
$RoundtripTime = $TestNetConnection.PingReplyDetails.RoundtripTime

# Add RoundTripTime -property to "main" object
$TestNetConnection | Add-Member NoteProperty 'RoundTripTime' "$RoundtripTime ms"



Try {
	$TestComputerSecureChannel = Test-ComputerSecureChannel
}
catch {
	
	$properties = @{
		'Error' = 'Error running Test-ComputerSecureChannel'
	}
	
	$TestComputerSecureChannel = @()
	$TestComputerSecureChannel += New-Object -TypeName PSObject -Prop $properties
}



############## html1

#Original
#$html1 = $Win32_ComputerSystem | Select Manufacturer, Model, Name, TotalPhysicalMemory| ConvertTo-Html -Fragment -PreContent "<h2>Win32_ComputerSystem</h2>" | Out-String

# Better formatting for tables    -As List
$html1 = $Win32_ComputerSystem | Select Manufacturer, Model, Name, TotalPhysicalMemory | ConvertTo-Html -As List -Fragment -PreContent "<h2>Win32_ComputerSystem</h2>" | Out-String

############## html2

#Original
#$html2 = $TestNetConnection | Select * | ConvertTo-Html -Fragment -PreContent "<h2>Test-NetConnection</h2>" | Out-String

# Better formatting for tables    -As List
#$html2 = $TestNetConnection | Select * | ConvertTo-Html -As List -Fragment -PreContent "<h2>Test-NetConnection</h2>" | Out-String

# Select properties manually - we are still missing sourceAddress
#$html2 = $TestNetConnection | Select ComputerName, RemoteAddress, PingSucceeded, TcpTestSucceeded, RemotePort, InterfaceAlias, InterfaceIndex, InterfaceDescription, NameResolutionSucceeded, IsAdmin, NetworkIsolationContext | ConvertTo-Html -As List -Fragment -PreContent "<h2>Test-NetConnection</h2>" | Out-String

# Added SourceIPAddress and RoundtripTime
$html2 = $TestNetConnection | Select ComputerName, RemoteAddress, sourceIPAddress, PingSucceeded, RoundtripTime, TcpTestSucceeded, RemotePort, InterfaceAlias, InterfaceIndex, InterfaceDescription, NameResolutionSucceeded, IsAdmin, NetworkIsolationContext | ConvertTo-Html -As List -Fragment -PreContent "<h2>Test-NetConnection</h2>" | Out-String


############## html3

#Original
#$html3 = $TestComputerSecureChannel | ConvertTo-Html -Fragment -PreContent "<h2>Test-ComputerSecureChannel</h2>" | Out-String

# Better formatting for tables    -As List
$html3 = $TestComputerSecureChannel | ConvertTo-Html -As List -Fragment -PreContent "<h2>Test-ComputerSecureChannel</h2>" | Out-String

##############

# Make html file
$PreContent = "<h1>Computer $($env:COMPUTERNAME)<br>Network Connectivity summary<br>$ReportRunDateTime</h1>"
$Title = "Computer $($env:COMPUTERNAME) Win32-summary"

$HTMLFile = "$PSScriptRoot\$($env:COMPUTERNAME)_NetworkConnectivityReport_$ReportRunDateTime.html"

ConvertTo-HTML -head $head -PostContent $html1, $html2, $html3 -PreContent $PreContent -Title $Title | Out-File $HTMLFile

################################################################################################

#region Regexp Match Evaluator

# Use regexp to highlight interesting values in tables

#Regex Replace MatchEvaluator
# This has all logics for changing cell colors
$ME_PingSucceeded = {
	param($match)
	
	#If PingSucceeded True -> Green
	if ([String]($match.Groups[3].Value) -eq 'True') {

		#Add green text-style to row
		"$($match.Groups[1].Value)<td bgcolor=`"green`"><font color=`"white`">$($match.Groups[3].Value)</font>$($match.Groups[4].Value)"

	}
	else {
		# If we did NOT succeed
		#Add red text-style to row
		"$($match.Groups[1].Value)<td bgcolor=`"red`"><font color=`"white`">$($match.Groups[3].Value)</font>$($match.Groups[4].Value)"
	}
}


$ME_RoundtripTime = {
	param($match)

	# This has more regexp groups than usually. Do use this as template for other tests
	
	#If Roundtriptime is less than or equal 4 milliseconds -> GREEN
	if ([double]::Parse($match.Groups[3].Value) -le 4) {

		#Add green text-style to row
		"$($match.Groups[1].Value)<td bgcolor=`"green`"><font color=`"white`">$($match.Groups[3].Value)$($match.Groups[4].Value)</font>$($match.Groups[5].Value)"

	} #If RoundtripTime is 5-10 milliseconds -> Yellow
	elseif (([double]::Parse($match.Groups[3].Value) -gt 4) -and ([double]::Parse($match.Groups[3].Value) -le 10)) {

		#Add yellow text-style to row
		"$($match.Groups[1].Value)<td bgcolor=`"yellow`">$($match.Groups[3].Value)$($match.Groups[4].Value)</font>$($match.Groups[5].Value)"
		
	} #If RoundtripTime is over 10 milliseconds -> RED
	elseif ([double]::Parse($match.Groups[3].Value) -gt 10) {

		#Add red text-style to row
		"$($match.Groups[1].Value)<td bgcolor=`"red`"><font color=`"white`">$($match.Groups[3].Value)$($match.Groups[4].Value)</font>$($match.Groups[5].Value)"

	}
}


# Change cell background color based on value in cell
# Uses Regex Replace MatchEvaluator

#<tr><td>PingSucceeded:</td><td>True</td></tr>
$regex = '^(<tr><td>PingSucceeded:<\/td>)(<td>)([a-zA-Z]*)(<\/td><\/tr>)$'

(Get-Content $HTMLFile) | Foreach {`
		[regex]::Replace($_, $regex, $ME_PingSucceeded) }`
| Out-File $HTMLFile

######
	
#<tr><td>RoundTripTime:</td><td>8 ms</td></tr>
$regex = '^(<tr><td>RoundTripTime:<\/td>)(<td>)([0-9]*)( ms)(<\/td><\/tr>)$'
	
(Get-Content $HTMLFile) | Foreach {`
		[regex]::Replace($_, $regex, $ME_RoundtripTime) }`
| Out-File $HTMLFile
	
	
#endregion Regexp Match Evaluator

# Open html file
Invoke-Item $HTMLFile


# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-html?view=powershell-6
# https://techontip.wordpress.com/2015/01/08/powershell-html-report-with-multiple-tables/
# https://blogs.technet.microsoft.com/heyscriptingguy/2013/04/01/working-with-html-fragments-and-files/

