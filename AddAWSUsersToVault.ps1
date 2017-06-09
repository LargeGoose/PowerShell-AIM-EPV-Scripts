# Define the FQDN for the REST APIs
$FQDN = 'https://pvwa.cybergoose.demo'
# Define the FQDN for the AIM REST API
$AFQDN = 'https://pvwa.cybergoose.demo'

##########################################################
# Get AWS credentials from CyberArk Vault using CyberArk AIM CCP
########################################################## 
"$(Get-Date) Using AIM to retrieve AWS credentials from the CyberArk Vault"
# The components of the AIM REST request
$appid = 'PowerShellOpen'
$safe = 'AWS'
$object = 'Cloud-Service-AWSAccounts-DemoAdminUser'
$ccpURI = $AFQDN + '/AIMWebService/api/Accounts?' + 'AppID=' + $appid + '&Safe=' + $safe + '&Object=' + $object
$result = $null
"$(Get-Date) $ccpURI"
$result = Invoke-RestMethod -Method Get -Uri $ccpURI -ContentType "application/json"
if ($result -eq $null) {
  "$(Get-Date) Failed to get AWS Keys from CyberArk Vault, exiting..."
}
else {
  # Split the CAOutput result into the Key and Secret
  $AWSAccessKey = $result.AWSAccessKeyID
  $AWSSecretKey = $result.Content
  # Before we start scanning AWS accounts we need an EPV service account we can search with
  $appid = 'PowerShellOpen'
  $safe = 'AWS'
  $object = 'Application-CyberArk-192.168.127.1-AWSAPIAdmin'
  $ccpURI = $FQDN + '/AIMWebService/api/Accounts?' + 'AppID=' + $appid + '&Safe=' + $safe + '&Object=' + $object
  $result = $null
  "$(Get-Date) Using AIM to retrieve EPV Admin credentials from the CyberArk Vault"
  "$(Get-Date) $ccpURI"
  $result = Invoke-RestMethod -Method Get -Uri $ccpURI -ContentType "application/json"
  if ($result -eq $null) {
    "$(Get-Date) Failed to get 'Account Administrator' credentials from CyberArk Vault"
  }
  else {
    "$(Get-Date) Credentials retrieved, logging in using REST APIs"
    $logonInfo = @{}
    $logonInfo.username = $result.UserName
    $logonInfo.password = $result.Content
    $loginURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logon'   
    $result = $null
    $result = Invoke-RestMethod -Method Post -Uri $loginURI -ContentType "application/json" -Body (ConvertTo-Json($logonInfo))
    if ($result -eq $null) {
    }
    else {
      "$(Get-Date) CyberArk Vault login successful"
      $logonToken = $result.CyberArkLogonResult
      $headers = @{ "Authorization" = $logonToken }
      "$(Get-Date) Credentials retrieved, logging in to AWS"
      # AWS authentication using access and secret key
      Initialize-AWSDefaults -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey -Region eu-west-2
      "$(Get-Date) Scanning AWS IAMUsers..."
      Foreach ($UserId  IN Get-IAMUsers) {
        $AccessKeys = Get-IAMAccessKey -UserName $UserId.UserName  
        # If the Account doesn't have an Access Key i.e. it's a password account, continue
        if ($AccessKeys.AccessKeyId -eq $null) {
          continue
        }
        #"$(Get-Date) Found AWS account " + $UserId.UserName + " with Access Key(s) "+ $AccessKeys.AccessKeyId
        #"$(Get-Date) Looking for account in the CyberArk Vault..."
        
        $searchAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts?Keywords=' + $UserId.UserName + '&Safe=AWS'
        $result = $null
        $result = Invoke-RestMethod -Method Get -Uri $searchAccountURI -headers $headers -ContentType "application/json"
        # If the account cannot be found it will be created...
        if ($result.Count -eq 0) {
          "$(Get-Date) The account " + $UserId.UserName + " was not in the CyberArk Vault, creating it..."
          # First we need to spin the AccessKeyID and get a new Secret
          # If the account has two access keys already we need to access the first one
          if ($AccessKeys.Count -gt 1) {
            Remove-IAMAccessKey -UserName $UserId.UserName -AccessKeyId $AccessKeys.AccessKeyId[0] -Force
          }
          $result = New-IAMAccessKey -UserName $UserId.UserName
          # Create an AWS account in the Vault
          $createAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Account'         
          $newAccounts = @{}
          $newAccount = @{}
          $newAccount.safe = "AWS"
          $newAccount.platformID = "AWSAccounts"
          ##### Base Account Properties #####
          $newAccount.address = "aws.amazon.com"
          $newAccount.password = $result.SecretAccessKey
          ##### the UserName value becomes the AWS IAM Username as displayed in PVWA #####
          $newAccount.username = $UserId.UserName
          ##### Extended properties are used for AWS details #####
          $properties = @(                      
            @{Key='AWSAccessKeyID';Value = $result.AccessKeyId}
          )             
          $newAccount.properties = $properties
          $newAccounts.account = $newAccount
          $result = $null
          "$(Get-Date) Attempting to create account in the CyberArk Vault"
          $result = Invoke-RestMethod -Method Post -Uri $createAccountURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json -InputObject $newAccounts -Depth 3)
          if ($result -eq $null) {
            "$(Get-Date) Failed to create the account in the CyberArk Vault"
          }
          else {
            "$(Get-Date) Account created successfully"
            $searchAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts?Keywords=' + $UserId.UserName + '&Safe=' + $newAccount.safe
            $result = $null
            $result = Invoke-RestMethod -Method Get -Uri $searchAccountURI -headers $headers -ContentType "application/json"
            if ($result -eq $null) {
              #"$(Get-Date) Failed to find the account in the CyberArk Vault"
            }
            else {
              #"$(Get-Date) Created account found..."
              $flagimmediateAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Accounts/' + $result.accounts.AccountID + '/ChangeCredentials'
              $headers = @{ "Authorization" = $logonToken; "ImmediateChangeByCPM" = "Yes"; "ChangeCredsForGroup" = "No" }
              $result = $null
              $result = Invoke-RestMethod -Method Put -Uri $flagimmediateAccountURI -headers $headers -ContentType "application/json"
              if ($result -eq $null) {
                "$(Get-Date) Failed to flag the account with immediate update in the CyberArk Vault"
              }
              else {
                "$(Get-Date) Account flagged for immediate change..."
              }                                          
            }
          }
        }   
      }
      "$(Get-Date) Removing AWS profile..."
      # Clear default AWS credentials so no PowerShell script in the same context can access them
      Remove-AWSCredentialProfile -ProfileName default -Force
      # use the old method just in case!
      Clear-AWSCredentials
      $logoffURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logoff'
      $result = $null
      $result = Invoke-RestMethod -Method Post -Uri $logoffURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json($logonInfo))
      if ($result -eq $null) {
        "$(Get-Date) Failed to loggoff from the CyberArk Vault"
      }
      else {
        "$(Get-Date) CyberArk Vault logoff successful"
      }
    }
  }
}