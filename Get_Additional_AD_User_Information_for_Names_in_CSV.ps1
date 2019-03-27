# Import givenName and surName from csv
# Find additional user information from Active Directory
# Export results to another csv file

# Petri.Paavola@yodamiitti.fi
# 27.3.2019


# Import names from csv file
# csv file has to have header which has surName,givenName -attributes
#
# surName,givenName
#
#$UserNamesInCSV = Import-Csv "$PSScriptRoot\nimet.csv"
$UserNamesInCSV = Import-Csv "C:\temp\Powershell\nimet.csv"


# File where to save information
#$outputfile = "$PSScriptRoot\UsersWithAdditionalInformation.csv"
$outputfile = "C:\temp\Powershell\UsersWithAdditionalInformation.csv"

# Base OU where to find users from
# This helps exclude for example admin accounts which have same name
$SearchBaseOU = "OU=users,OU=root,DC=org,DC=yodamiitti,DC=fi"


# Initialize variable where user AD information is stored
$ADUserInformation = @()

# Loop each user and get additional information from Active Directory
foreach ($user in $UserNamesInCSV) {
    $givenName = $user.givenName
    $surName = $user.surName

    # Get ADUser information
    $UserInfo = get-aduser -Filter {(givenName -eq $givenName) -AND (surName -eq $surName)} -Properties givenName,surName,DisplayName,sAMAccountName,mail -SearchBase $SearchBaseOU

    # Test if we found 1 or more results
    if($UserInfo -is [ARRAY]) {
        # Search returned multiple user accounts.
        # For example Admin accounts can have same givenName and surName than normal accounts
        #
        # Decide what to do in this case!

        Write-Output "Found multiple users for search: givenName=$givenName surname=$surName"
        Write-Output "$UserInfo"

        # Add user to destination csv without additional information so we know we didn't get results to all users
        $EmptyUserObject = New-Object Object
        $EmptyUserObject | Add-Member -NotePropertyName givenName -NotePropertyValue $givenName
        $EmptyUserObject | Add-Member -NotePropertyName surName -NotePropertyValue $surName

        $ADUserInformation += $EmptyUserObject

    } elseif($UserInfo -eq $null) {
        # Search did not return any results
        #
        # Add user to destination csv without additional information so we know we didn't get results to all users

        Write-Output "Did not find ADUser with information: givenName=$givenName surname=$surName"

        $EmptyUserObject = New-Object Object
        $EmptyUserObject | Add-Member -NotePropertyName givenName -NotePropertyValue $givenName
        $EmptyUserObject | Add-Member -NotePropertyName surName -NotePropertyValue $surName

        $ADUserInformation += $EmptyUserObject

    } else {
        # There was only 1 user account with givenName and surName which is what we are looking for

        # Add user information to array of ADUser objects
        $ADUserInformation += $UserInfo
    }
}

# Export ADUser information to csv-file
$ADUserInformation | Select-Object surName,givenName,displayName,sAMAccountName,mail | Export-Csv -Path "$outputfile" -NoTypeInformation
