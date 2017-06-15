##########################################################
# Automation of new AWS Linux instance using AIM credentials
# Automation of AWS Security Group using said credentials
# Registration of new instance to CyberArk Vault using different AIM credentials
# plagiarised, prettified and generally made to work by angus.herron@cyberark.com
##########################################################
# Note: Any changes to the script done after the script has 
# been signed to the Vault will cause this script to fail!
##########################################################

# Define the FQDN for the REST APIs
$FQDN = 'http://pvwa.cybergoose.demo'
# Define the FQDN for the AIM REST API
$AFQDN = 'http://pvwa.cybergoose.demo'

##########################################################
# A function to create a random key name. Pass a number as the length
##########################################################
function GenerateKeyName ($length) {
  return -join ((65..90) + (97..122) | Get-Random -Count $length | % {[char]$_})
}
##########################################################
# A function to check the instance status
##########################################################
function WaitForState ($instanceid, $desiredstate) {
  while ($true) {
    $a = Get-EC2Instance -Instance $instanceid
    $state = $a.Instances[0].State.Name
    if ($state -eq $desiredstate) {
      break;
    }
	"$(Get-Date) Current State = $state, Waiting for Desired State=$desiredstate"
	Sleep -Seconds 5
  }
}
##########################################################
# Get AWS credentials from CyberArk Vault using CyberArk AIM CCP
########################################################## 
"$(Get-Date) Using AIM to retrieve AWS credentials from the Vault"
# The components of the AIM REST request
$appid = 'AWS_PowerShell'
$safe = 'AWS'
$object = 'Cloud-Service-AWSAccounts-DemoAdminUser'
$ccpURI = $AFQDN + '/AIMWebService/api/Accounts?' + 'AppID=' + $appid + '&Safe=' + $safe + '&Object=' + $object
$result = $null
$result = Invoke-RestMethod -Method Get -Uri $ccpURI -ContentType "application/json"
if ($result -eq $null) {
  "$(Get-Date) Failed to get AWS Keys from CyberArk Vault, exiting..."
}
else {
  "$(Get-Date) Credentials retrieved, logging in to AWS"
  # Allocate the $creds result into the Key and Secret
  $AWSAccessKey = $result.AWSAccessKeyID
  $AWSSecretKey = $result.Content
  # Initialise AWS authentication using access and secret key
  Initialize-AWSDefaults -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey -Region eu-west-2
  # Create a new, random, keyname
  $myKeyName = GenerateKeyName(10)
  # Generate a new EC2 Key Pair using the created name
  $myPSKeyPair = New-EC2KeyPair -KeyName $myKeyName
  # Do we have the security group that will allow SSH access to our new instance yet? Security Groups are permanent until deleted
  $sg = Get-EC2SecurityGroup | ? { $_.GroupName -eq "EC2SSHSecurityGroup"}
  if ($sg -eq $null) {
    # If not, create a Security Group
    $sg = New-EC2SecurityGroup -GroupName EC2SSHSecurityGroup -GroupDescription "Security group for SSH only to EC2 instances"
    # 22, i.e. SSH only
    Grant-EC2SecurityGroupIngress -GroupName EC2SSHSecurityGroup -IpPermissions @{IpProtocol = "tcp"; FromPort = 22; ToPort = 22; IpRanges = @("0.0.0.0/0")}
  }
  "$(Get-Date) Creating a new instance in AWS"
  # Start by finding the correct AMI ## THIS DOES NOT EXIST BY DEFAULT
  $a = Get-EC2Image -Owner self -Filters @{Name = “name”; Values = “Base_Linux_AMI”}
  $imageid = $a.ImageId
  # Once we have found the ImageId then we can create one
  $a = New-EC2Instance -ImageId $imageid -MinCount 1 -MaxCount 1 -InstanceType t2.micro -KeyName $myKeyName -SecurityGroups EC2SSHSecurityGroup
  $instanceid = $a.Instances[0].InstanceId
  "$(Get-Date) New Instance is being created: $instanceid"
  # Scan and snooze until the new instance running...
  WaitForState $instanceid "Running"
  # Snooze over, we have the ID
  $a = Get-EC2Instance -Instance $instanceid
  $publicIP = $a.Instances[0].PublicIpAddress
  $publicDNS = $a.Instances[0].PublicDnsName
  "$(Get-Date) Using AIM to retrieve a credentail with 'Add Account' rights"
  ##########################################################
  # Get AWS credentials from CyberArk Vault using CyberArk AIM CCP
  ########################################################## 
  "$(Get-Date) Using AIM to retrieve credentials from the Vault"
  # The components of the AIM REST request
  $appid = 'AWS_PowerShell'
  $safe = 'AWS'
  $object = 'Application-CyberArk-192.168.127.1-AWSAPIAdmin'
  $ccpURI = $AFQDN + '/AIMWebService/api/Accounts?' + 'AppID=' + $appid + '&Safe=' + $safe + '&Object=' + $object
  $result = $null
  $result = Invoke-RestMethod -Method Get -Uri $ccpURI -ContentType "application/json"
  if ($result -eq $null) {
    "$(Get-Date) Failed to get 'Account Administrator' credentials from CyberArk Vault"
  }
  else {
    "$(Get-Date) Credentials retrieved, logging in to REST APIs"
    # Allocate the $creds result into the Key and Secret
    $logonInfo = @{}
    $logonInfo.username = $result.UserName
    $logonInfo.password = $result.Content
    ##########################################################
    # Use REST APIs to logon to the CyberArk Vault
    ########################################################## 
    $loginURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logon'
    #login to the Vault
    $result = Invoke-RestMethod -Method Post -Uri $loginURI -ContentType "application/json" -Body (ConvertTo-Json($logonInfo))
    "$(Get-Date) Vault login successful"
    $logonToken = $result.CyberArkLogonResult
    # Define the Account Management URL
    $createAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Account'
    # Account parameters
    $newAccounts = @{}
    $newAccount = @{}
    $newAccount.safe = "AWS"
	# The platform needs to be of type UnixSSHKeys
    $newAccount.platformID = "AWSLinuxServers"
    # We could use the IP or DNS address, IP is neater...
    $newAccount.address = $publicIP
    #$newAccount.address = $publicDNS
    # The default Linux account is always ec2-user...
    $newAccount.username = "ec2-user"
    # The 'password' is the SSH Key created earlier
    $newAccount.password = $myPSKeyPair.KeyMaterial
    $newAccount.accountName = $instanceid
    # Add the account to create to the accounts array
    $newAccounts.account = $newAccount
    # Set the authorisation token in the headers for the REST call
    $headers = @{ "Authorization" = $logonToken }
    ##########################################################
    # Use REST APIs to create the account in the CyberArk Vault
    ##########################################################
    $result = Invoke-RestMethod -Method Post -Uri $createAccountURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json($newAccounts))
    "$(Get-Date) Account created successfully"  
    ##########################################################
    # Use REST APIs to logoff from the Vault
    ##########################################################
    $logoffURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logoff'
    $result = Invoke-RestMethod -Method Post -Uri $logoffURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json($logonInfo)) 
    "$(Get-Date) Vault logoff successful"
    "$(Get-Date) Finished provisioning instance in AWS and the privileged account of instance $instanceid, with IP address $publicIP in the CyberArk Vault"
    # Clear default AWS credentials so no PowerShell script in the same context can access them
    Remove-AWSCredentialProfile -ProfileName default -Force
  }
}
