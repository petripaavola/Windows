# Powershell_toolbox_PetriPaavola.ps1
# 20181204
#
# INITIAL VERSION. THIS WILL BE UPDATED IN 24 hours.
#
# Collection of Powershell-commands, tips and tricks mostly related to Windows management
#
# Yes, this is HUGE script and it will not get smaller. Use search to find interesting stuff.
# Everything should work :) I update this regurlarly as this is the script I'm also using personally.
#
# Petri.Paavola@yodamiitti.fi
#
# This script came from
# https://github.com/petripaavola


# Just to make sure we will NEVER ever run this script
Write-Host "Do NOT ever ever ever EVER try to run me!" -Foregroundcolor "Red"
Pause
Exit


############################################################

# Check executionpolicies status
get-executionpolicy -list

# Set executionpolicy bypass for different scopes

# Allow running Powershell scripts
# These does NOT need Admin rights
Set-Executionpolicy -ExecutionPolicy bypass -Scope Process
Set-Executionpolicy -ExecutionPolicy bypass -Scope CurrentUser

# Allow running Powershell scripts machine wide
# Need Admin rights
Set-Executionpolicy -ExecutionPolicy bypass -Scope LocalMachine
Set-Executionpolicy -ExecutionPolicy bypass
Set-Executionpolicy bypass


# Bypass Powershell executionpolicies. This bypasses enforced signature requirement
# Run Powershell file line by line as commands
powershell.exe -noprofile -command " & { get-content C:\temp\Powershell\Bypass_executionpolicy.ps1 | foreach { if($_ -ne '') { iex $_ } } } "

############################################################

# Powershell ISE
$psise

############################################################
