# Define the FQDN for the REST APIs
$FQDN = 'https://components.cybergoose.local'

# Define the Safe that the account will be moved from
$fromSafe = "AWS"
#$fromSafe = "Azure"
# Define the Safe that the account will be moved to
$toSafe = "Azure"
#$toSafe = "AWS"
# Define the account to be moved
$accountToBeMoved = "testserver.test.com"

# Debug function for JSon
function debug ($thing)
{
    $thing | ConvertTo-Json -Depth 3
}

# Create a logger
function log ($logtext)
{
    Write-Host $logtext
    # $logtext | Add-Content "$PSScriptRoot\log.log"
}

# Authentication
# Set the default EPV REST administrator user
$admin = "RestAdmin"
# Prompt for password
# $SecurePassword = Read-Host -Prompt "Please enter password for '$admin'" -AsSecureString
# $pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))
$pw = "Cyberark1"

$logonInfo = @{}
$logonInfo.username = $admin
$logonInfo.password = $pw
$loginURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logon'   
$result = $null
$result = Invoke-RestMethod -Method Post -Uri $loginURI -ContentType "application/json" -Body (ConvertTo-Json($logonInfo))
if ($result -eq $null) {
  log("$(Get-Date) CyberArk Vault login unsuccessful")
}
else {
  log("$(Get-Date) CyberArk Vault login successful")
  $logonToken = $result.CyberArkLogonResult
  $headers = @{ "Authorization" = $logonToken }

  ########################################################
  # We are logged in and the authorization header is set #
  ########################################################

  # We need to Account ID to access the account details
  log("$(Get-Date) Searching for the account ""$accountToBeMoved"" in the safe ""$fromSafe"" in the CyberArk Vault")
  $searchAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts?Keywords=' + $accountToBeMoved + '&Safe=' + $fromSafe
  $result = Invoke-RestMethod -Method Get -Uri $searchAccountURI -headers $headers -ContentType "application/json"
  if (($result | Select -ExpandProperty Count) -eq 0) {
    log("$(Get-Date) Failed to find the account ""$accountToBeMoved"" in the CyberArk Vault")
  }
  else {
    #debug($result)
    # We need to AccountID later so we need to store it
    $accountID = $result.accounts.AccountID
    log("$(Get-Date) The current AccountID is  ""$accountID""")
    # We have the account details so we need to create a new account object
    $wrapper = @{}
    $account = @{}
    # The details we get back from the search are wrongly named for the new account...
    foreach ($property in $result.accounts.properties) {
      switch ($property.key) {
        "Name" {$account.accountName = $property.value}
        "PolicyID" {$account.platformID = $property.value}
        "Safe" {$account.safe = $toSafe}
        "Address" {$account.address = $property.value}
        "UserName" {$account.username = $property.value}
        default {$account.$($property.key) = $property.value}
      }                            
    }
    # Now do the internal properties
    $properties = @()
    foreach ($property in $result.accounts.internalproperties) {
      switch ($property.Key) {
        "CreationMethod" {$properties += @{Key="CreationMethod"; Value="PowerShell Account Move Script"}}
        default {$properties += @{Key=$property.key; Value=$property.value}}
      }
    }
    $account.properties = $properties
    # Account copied now we need the password
    $getAccountValueURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts/' + $accountID + '/Credentials'
    $result = Invoke-RestMethod -Method Get -Uri $getAccountValueURI -headers $headers -ContentType "application/json" 
    $account.password = $result
    $wrapper.account = $account
    $addAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Account'
    # Add the new account
    $result = Invoke-WebRequest -Method POST -Uri $addAccountURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json -InputObject $wrapper -Depth 3)
    if ($result.StatusCode -ne 201) {
      log("$(Get-Date) There was a problem creating the account")
      debug($result)
    }
    else {
      log("$(Get-Date) The new account was created in ""$toSafe""")
      $searchAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts?Keywords=' + $accountToBeMoved + '&Safe=' + $toSafe
      $result = Invoke-RestMethod -Method Get -Uri $searchAccountURI -headers $headers -ContentType "application/json"
      if (($result | Select -ExpandProperty Count) -eq 0) {
        log("$(Get-Date) Failed to find the the account ""$accountToBeMoved"" in the CyberArk Vault")
      }
      else {
        log("$(Get-Date) The new AccountID is  ""$($result.accounts.AccountID)""")
        # So we have created a new account with exactly the same properties as the old account.
        # Now we need to delete the old account
        $deleteAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts/' + $accountID
        $result = Invoke-WebRequest -Method Delete -Uri $deleteAccountURI -headers $headers -ContentType "application/json"
        if ($result.StatusCode -eq 200) {
          log("$(Get-Date) Account ""$accountToBeMoved"" moved successfully from ""$fromSafe"" to ""$toSafe""")
        }
        else {
          log("$(Get-Date) There was a problem deleting the old account")
          debug($result)
        }
      }
    }
    
  }

  # Clear up and logoff
    $logoffURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/Logoff'   
    $result = $null
    $result = (Invoke-WebRequest -Method Post -Uri $logoffURI -ContentType "application/json" -headers $headers).statuscode
    if ($result -eq 200) {
      log("$(Get-Date) CyberArk Vault logoff successful")
    }
    else {
      log("$(Get-Date) CyberArk Vault logoff unsuccessful")
    }
}


