# Get all boot time entries from local system and show Graph
# Works also with Windows 7 Powershell 2.0
#
# Petri.Paavola@yodamiitti.fi
#

# Windows 7 Powershell 2.0 compatibility
#$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

# load the appropriate assemblies 
[void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
[void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms.DataVisualization")


#$startTime = Get-Date -Day ((Get-Date).AddDays(-180).Day) -Hour 0 -Minute 0 -Second 0
#$endTime = Get-Date -Hour 0 -Minute 0 -Second 0

$boottimes = @{}

# With Powershell 3.0+ this would be done
#$boottimes = [ordered]@{}


# create chart object 
$Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart 
$Chart.Width = 750
$Chart.Height = 400
$Chart.Left = 20
$Chart.Top = 20

# create a chartarea to draw on and add to chart 
$ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 
$Chartarea.AxisY.Title = "Seconds"
$Chartarea.AxisX.Title = "Date"
$Chart.ChartAreas.Add($ChartArea)


[void]$Chart.Series.Add("MainPathBootTime")
$Chart.Series["MainPathBootTime"].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line

[void]$Chart.Series.Add("BootPostBootTime")
$Chart.Series["BootPostBootTime"].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line


# legend 
$legend = New-Object system.Windows.Forms.DataVisualization.Charting.Legend
$legend.name = "Legend1"
$Chart.Legends.Add($legend)



# Get OS Install Date
$ComputerInstallDate = ([WMI] "").ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate).ToString("yyyy-MM-dd")
Write-Output "Computer installed: $($ComputerInstallDate)"

[void]$Chart.Titles.Add("$($env:COMPUTERNAME) Boot Times (OS InstallDate $ComputerInstallDate)")
$Chart.Titles[0].Font = "Arial,13pt"
$Chart.Titles[0].Alignment = "topCenter"

$eventList = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Diagnostics-Performance/Operational"; id=100}

$DateValues = @()
$BootTimeValues = @()
$PostBootTimeValues = @()

foreach ($event in $eventList) {

	$eventXML = [xml]$event.ToXml()
	$bootstart = $eventXML.SelectSingleNode("//*[@Name='BootStartTime']")."#text"
	$bootend   = $eventXML.SelectSingleNode("//*[@Name='BootEndTime']")."#text"
	$boottime  = $eventXML.SelectSingleNode("//*[@Name='BootTime']")."#text"
	$mainboottime = $eventXML.SelectSingleNode("//*[@Name='MainPathBootTime']")."#text"
	$postboottime = $eventXML.SelectSingleNode("//*[@Name='BootPostBootTime']")."#text"

	$pos = $bootstart.IndexOf("T")
	$bootstartDate = $bootstart.Substring(0, $pos)
	$bootstartTime = $bootstart.Substring($pos+1)
	$pos = $bootstartTime.IndexOf(".")
	$bootstartTime = $bootstartTime.Substring(0, $pos)
	
	$bootstart = $bootstart.replace('T','_')

	$pos = $bootend.IndexOf("T")
	$bootendDate = $bootend.Substring(0, $pos)
	$bootendTime = $bootend.Substring($pos+1)
	$pos = $bootendTime.IndexOf(".")
	$bootendTime = $bootendTime.Substring(0, $pos)

	
	$bootend = $bootend.replace('T','_')
			
	# Change date/time to Finnish format (sorry :)    day.month.year
	$day = $bootstart.Tostring().SubString(8,2)
	$month = $bootstart.Tostring().SubString(5,2)
	$year = $bootstart.Tostring().SubString(0,4)
	$bootStartTimeDDMMYYY = "$($day).$($month).$($year)"
	
	$boottime = [Math]::Truncate($boottime/1000)
	$mainboottime = [Math]::Truncate($mainboottime/1000)
	$postboottime = [Math]::Truncate($postboottime/1000)
	
	$boottimes.add($bootstart, $mainboottime)

	$DateValues += $bootStartTimeDDMMYYY
	$BootTimeValues += $mainboottime
	$PostBootTimeValues += $postboottime


	Write-Output "$($env:COMPUTERNAME), Date:$($bootStartTimeDDMMYYY), BootStart:$($bootstartTime), BootEnd:$($bootendTime), MainBootTime:$($mainboottime), PostBootTime:$($postboottime), BootTime:$($boottime)"

	$bootcount=""; $bootstart=""; $bootend=""; $boottime=""; $mainboottime=""; $postboottime="";
}   
  
    

# Reverse values on array. Otherwise graph will show values in wrong order
# Reason is Windows 7 Powershell 2.0 compatibility
[array]::Reverse($DateValues)
[array]::Reverse($BootTimeValues)
[array]::Reverse($PostBootTimeValues)

$Chart.Series["MainPathBootTime"].Points.DataBindXY($DateValues, $BootTimeValues)
$Chart.Series["BootPostBootTime"].Points.DataBindXY($DateValues, $PostBootTimeValues)


# display the chart on a form 
$Chart.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right -bor 
                [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left 
$Form = New-Object Windows.Forms.Form 
$Form.Text = "PowerShell Chart" 
$Form.Width = 800 
$Form.Height = 500 
$Form.controls.add($Chart) 
$Form.Add_Shown({$Form.Activate()}) 
$Form.ShowDialog()
