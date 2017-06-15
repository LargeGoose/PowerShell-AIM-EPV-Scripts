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
# Get AWS credentials from CyberArk Vault using CyberArk AIM
# Note: Any changes to the script done after the script has 
# been signed to the Vault will cause this call to fail.
########################################################## 
"$(Get-Date) Using AIM to retrieve AWS credentials from the Vault"
$CACLI = 'C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'
$appid = 'AWS_PowerShell'
$query = 'Safe=AWS;Folder=Root;Object=Cloud-Service-AWSAccounts-DemoAdminUser'
$output = 'PassProps.AWSAccessKeyID,Password'
$CAOutput = &$CACLI GetPassword /p AppDescs.AppId=$appid /p Query=$query /o $output
if ($CAOutput -eq $null) {
  "$(Get-Date) Failed to get AWS Keys from CyberArk Vault"
}
else {
  "$(Get-Date) Credentials retrieved, logging in to AWS"
  # AWS authentication using access and secret key
  $AWSAccessKey = $CAOutput.Split(",")[0]
  $AWSSecretKey = $CAOutput.Split(",")[1]
  Initialize-AWSDefaults -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey -Region eu-west-2
  # Create a Key Pair for the new instance and save a copy locally
  $myKeyName = GenerateKeyName(10)
  $myPSKeyPair = New-EC2KeyPair -KeyName $myKeyName
  "$($myPSKeyPair.KeyMaterial)" | out-file -encoding ascii -filepath $env:temp\$myKeyName.pem
  "KeyName: $($myPSKeyPair.KeyName)" | out-file -encoding ascii -filepath $env:temp\$myKeyName.pem -Append
  "KeyFingerprint: $($myPSKeyPair.KeyFingerprint)" | out-file -encoding ascii -filepath $env:temp\$myKeyName.pem -Append
}
#Do we have the security group yet?
$sg = Get-EC2SecurityGroup | ? { $_.GroupName -eq "EC2RDPSecurityGroup"}
if ($sg -eq $null) {
  #Create a Security Group
  $sg = New-EC2SecurityGroup -GroupName EC2RDPSecurityGroup -GroupDescription "Security group for RDP only to EC2 instances"
  Grant-EC2SecurityGroupIngress -GroupName EC2RDPSecurityGroup -IpPermissions @{IpProtocol = "tcp"; FromPort = 3389; ToPort = 3389; IpRanges = @("0.0.0.0/0")}
}
"$(Get-Date) Connected to AWS"
#Start creating new instance in AWS
$a = Get-EC2ImageByName -Name WINDOWS_2012R2_BASE
$imageid = $a.ImageId
$a = New-EC2Instance -ImageId $imageid -MinCount 1 -MaxCount 1 -InstanceType t2.micro -KeyName $myKeyName -SecurityGroups EC2RDPSecurityGroup
$instanceid = $a.Instances[0].InstanceId
"$(Get-Date) New Instance is being created: $instanceid"
WaitForState $instanceid "Running"
$a = Get-EC2Instance -Instance $instanceid
$publicIP = $a.Instances[0].PublicIpAddress
$publicDNS = $a.Instances[0].PublicDnsName
"$(Get-Date) Waiting for the new instance ($instanceid) password to become available"
$ec2_password = $null
# Wait until the password is available. According to AWS this could be up to 30 minutes.
$KeyFilePath = "$env:temp\$myKeyName.pem"
Sleep -Seconds 30
while ($ec2_password -eq $null) {
  try {
    $ec2_password = Get-EC2PasswordData -InstanceId $instanceid -PemFile $KeyFilePath -Decrypt
  }
  catch {
    "$(Get-Date) Still waiting for password to be available..."
    Sleep -Seconds 30
  }
}
# This removes the only way to recover the password from AWS!
Remove-Item "$KeyFilePath"
"$(Get-Date) Got the new instance password! Lets create a new account in the Vault."
"$(Get-Date) Using AIM to retrieve a credentail with 'Add Account' rights"
$CACLI = 'C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'
$appid = 'AWS_PowerShell'
$query = 'Safe=AWS;Folder=Root;Object=Application-CyberArk-192.168.127.1-AWSAPIAdmin'
$output = 'PassProps.userName,Password'
$CAOutput = &$CACLI GetPassword /p AppDescs.AppId=$appid /p Query=$query /o $output
if ($CAOutput -eq $null) {
  "$(Get-Date) Failed to get AWS Keys from CyberArk Vault"
}
else {
  "$(Get-Date) Credentials retrieved, logging in to REST APIs"
  $username = $CAOutput.Split(",")[0]
  $password = $CAOutput.Split(",")[1]
  $logonInfo = @{}
  $logonInfo.username = $username
  $logonInfo.password = $password

  $FQDN = 'http://pvwa.cybergoose.demo'
  $loginURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logon'
  #login to the Vault
  $result = Invoke-RestMethod -Method Post -Uri $loginURI -ContentType "application/json" -Body (ConvertTo-Json($logonInfo))
  "$(Get-Date) Vault login successful"
  $logonToken = $result.CyberArkLogonResult

  $createAccountURI = $FQDN + '/PasswordVault/WebServices/PIMServices.svc/Account'

  #account parameters
  $newAccounts = @{}
  $newAccount = @{}
  $newAccount.safe = "AWS"
  $newAccount.platformID = "AWSWindowsServers"
  $newAccount.address = $publicIP
  #$newAccount.address = $publicDNS
  $newAccount.username = "Administrator"
  $newAccount.password = $ec2_password
  $newAccount.accountName = $instanceid
  $newAccounts.account = $newAccount

  $headers = @{ "Authorization" = $logonToken }

  #create the account in the Vault
  $result = Invoke-RestMethod -Method Post -Uri $createAccountURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json($newAccounts))
  "$(Get-Date) Account created successfully"
 
  $logoffURI = $FQDN + '/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logoff'
  #logoff from the Vault
  $result = Invoke-RestMethod -Method Post -Uri $logoffURI -headers $headers -ContentType "application/json" -Body (ConvertTo-Json($logonInfo)) 
  "$(Get-Date) Vault logoff successful"

  "$(Get-Date) Finished provisioning instance in AWS and the privileged account of instance $instanceid, with IP address $publicIP in the CyberArk Vault"

  # Clear AWS credentials
  Clear-AWSDefaults
}
