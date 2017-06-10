# This script was designed to get creds for AWS so the result.AWSAccessKeyID is used

# Define the FQDN for the AIM REST API
$AFQDN = 'http://pvwa.cybergoose.demo'
# THIS SHOULD BE HTTPS WITH THE CERTIFICATE SERIAL NUMBER USED FOR APPLICATION AUTHENTICATION

##########################################################
# Get credentials from CyberArk Vault using CyberArk AIM CCP
########################################################## 
"$(Get-Date) Using AIM to retrieve credentials from the Vault"
# The components of the AIM REST request
$appid = 'AWS_PowerShell'
$safe = 'AWS'
$object = 'Cloud-Service-AdminUser'
# Build the full URI
$ccpURI = $AFQDN + '/AIMWebService/api/Accounts?' + 'AppID=' + $appid + '&Safe=' + $safe + '&Object=' + $object
# Preset $result to $null
$result = $null
# This is the actual REST call
$result = Invoke-RestMethod -Method Get -Uri $ccpURI -ContentType "application/json"
if ($result -eq $null) {
  "$(Get-Date) Failed to get AWS Keys from CyberArk Vault, exiting..."
}
else {
  "$(Get-Date) Credentials retrieved, you can now use them login to AWS!"
  # Allocate the $result into the Key and Secret
  $AWSAccessKey = $result.AWSAccessKeyID
  $AWSSecretKey = $result.Content
}
