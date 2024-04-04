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
    [string]$ProviderRegion,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMAccessKey,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMSecretAccessKey
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

#region Authenticate first with the provider IAM access key assuming the necessary role
$initialAuthsetCredParams = @{
    AccessKey = (decryptPassword($ProviderIAMAccessKey))
    SecretKey = (decryptPassword($ProviderIAMSecretAccessKey))
    Scope     = 'Private'
}
Set-AWSCredential @initialAuthsetCredParams

$useStsRoleParams = @{
    RoleArn = $ProviderIAMRoleArn
    DurationInSeconds =  900
    RoleSessionName = (New-Guid)
    Region = $ProviderRegion
}

## Assume the IAM user role that was pre-configured
## Assuming 15 minutes is enough time to enumerate all IAM users
$credentials = Use-STSRole @useStsRoleParams

$roleAuthSetCredParams = @{
    AccessKey = $credentials.Credentials.AccessKeyId
    SecretKey = $credentials.Credentials.SecretAccessKey
    Scope     = 'Private'
    SessionToken = $credentials.Credentials.SessionToken
}
Set-AWSCredential @roleAuthSetCredParams
#endregion




## TODO: should temporary access keys and long-terms keys be treated the same in this provider?
## You cannot get the secret key. need to figure out a way to get an access denied by forcing an action

## Using Parallel because running Get-IAMUser is pretty slow
Get-IAMUserList | ForEach-Object -ThrottleLimit 10 -Parallel {

    $creds = $using:credentials
    $userName = $_.UserName

    try {
        
        Get-IAMAccessKey -UserName $userName
    
    } catch [Amazon.IdentityManagement.Model.NoSuchEntityException] {
        Write-Output -InputObject "No login profile found for IAM user [$userName]."
    }
}