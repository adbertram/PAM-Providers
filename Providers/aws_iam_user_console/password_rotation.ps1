#requires -version 7
#requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.1.540'}
#requires -Modules @{ModuleName='AWS.Tools.SecurityToken';ModuleVersion='4.1.540'}
#requires -Modules @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.1.540'}

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^arn:aws:iam::\d{12}:role\/[\w+=,.@-]+$')]
    [string]$ProviderIAMRoleArn,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProviderRegion,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMUserAccessKey,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMUserSecretAccessKey,

    [Parameter(Mandatory)]
    [securestring]$NewPassword
)

$ErrorActionPreference = 'Stop'

## This is useful to see what parameters DVLS passed to the script
Write-Output -InputObject "Running script with parameters: $($PSBoundParameters | Out-String)"

#region functions
function decryptPassword ([securestring]$Password) {
    # Decrypts a secure string password
    try {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        ## Clear the decrypted password from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}
#endregion

## Store the credential temporarily in the session
$setCredParams = @{
    AccessKey = (decryptPassword($ProviderIAMUserAccessKey))
    SecretKey = (decryptPassword($ProviderIAMUserSecretAccessKey))
    Scope     = 'Private'
}
Set-AWSCredential @setCredParams

## Assume the IAM user role that was pre-configured
## Assuming 15 minutes is enough time to enumerate all IAM users
$credentials = Use-STSRole -RoleArn $ProviderIAMRoleArn -DurationInSeconds 900 -RoleSessionName (New-Guid) -Region $ProviderRegion

$setCredParams = @{
    AccessKey    = $credentials.Credentials.AccessKeyId
    SecretKey    = $credentials.Credentials.SecretAccessKey
    Scope        = 'Private'
    SessionToken = $credentials.Credentials.SessionToken
}
Set-AWSCredential @setCredParams

Update-IAMLoginProfile -UserName $UserName -Password (decryptPassword($NewPassword))

if ($Result) {
    Return $True
} else {
    Write-Error "Failed to Update Secret"
}
