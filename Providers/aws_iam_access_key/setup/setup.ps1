#requires -Modules @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.1.540'}

<#
.SYNOPSIS
Sets up the AWS IAM environment for Devolutions AnyIdentity provider, including IAM user, access key, and role with specific permissions.

.DESCRIPTION
This script prepares the AWS IAM environment required for the Devolutions AnyIdentity provider. It creates an IAM user, 
generates an access key, establishes IAM roles, and attaches necessary policies for managing AWS IAM access keys. The 
setup ensures proper permissions are in place for secure AnyIdentity provider operations.

.PARAMETER ProviderRegion
Specifies the AWS region where the IAM user and role will be created.

.PARAMETER ProviderIAMAccessKey
The AWS access key used for authentication. This should have the necessary permissions to create users, roles, and policies.

.PARAMETER ProviderIAMSecretAccessKey
The AWS secret access key corresponding to the ProviderIAMAccessKey.

.PARAMETER AnyIdentityIAMUserName
(Optional) The name of the IAM user to be created. Defaults to 'devolutions_anyidentity_provider_iam_access_key'.

.PARAMETER AnyIdentityIAMRoleName
(Optional) The name of the IAM role to be created. Defaults to 'IAMChangeAllAccessKeys'.

.PARAMETER PermissionBoundaryPolicyName
(Optional) The name of the permission boundary policy to be attached to the IAM user. Defaults to 'IAMChangeIAMAccessKeysPermissionBoundary'.

.PARAMETER RolePermissionPolicyName
(Optional) The name of the permission policy to be attached to the IAM role. Defaults to 'IAMChangeIAMAccessKeysRole'.

.PARAMETER UserPermissionPolicyName
(Optional) The name of the user permission policy. Defaults to 'IAMChangeIAMAccessKeysUserPolicy'.

.EXAMPLE
PS> .\setup.ps1 -ProviderRegion 'us-east-1' -ProviderIAMAccessKey 'AKIA...' -ProviderIAMSecretAccessKey (ConvertTo-SecureString 'yourSecretKey' -AsPlainText -Force)

Executes the setup script with the specified AWS region, IAM access key, and secret access key. This example demonstrates
the complete setup process, including the creation of the IAM user, role, and necessary policies.

.NOTES
This script requires AWS PowerShell modules: AWS.Tools.IdentityManagement, AWS.Tools.SecurityToken, and AWS.Tools.Common.
Ensure these are installed and available before running the script.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProviderRegion,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMAccessKey,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ProviderIAMSecretAccessKey,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AnyIdentityIAMUserName = 'devolutions_anyidentity_provider_iam_access_key',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AnyIdentityIAMRoleName = 'IAMChangeAllAccessKeys',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PermissionBoundaryPolicyName = 'IAMChangeIAMAccessKeysPermissionBoundary',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RolePermissionPolicyName = 'IAMChangeIAMAccessKeysRole',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserPermissionPolicyName = 'IAMChangeIAMAccessKeysUserPolicy'
)

$ErrorActionPreference = 'Stop'

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

function createPolicy($type, $name, $userArn) {
    try {
        $policyDoc = Get-Content -Path "$PSScriptRoot\policies\$type.json" -Raw
        if ($userArn) {
            $policyDoc = $policyDoc.replace('<user arn here>', $userArn)
        }
        New-IAMPolicy -PolicyName $name -PolicyDocument $policyDoc
    } catch [Amazon.IdentityManagement.Model.EntityAlreadyExistsException] {
        Write-Warning -Message "A policy named [$name] already exists."
        Get-IAMPolicies -Scope Local | Where-Object { $_.PolicyName -eq $name }
    }
}
#endregion

#region Authenticate to AWS using the IAM access key with permission to set up IAM user, access key and role
$initialAuthsetCredParams = @{
    AccessKey = (decryptPassword($ProviderIAMAccessKey))
    SecretKey = (decryptPassword($ProviderIAMSecretAccessKey))
    Scope     = 'Script'
}
Set-AWSCredential @initialAuthsetCredParams

Set-DefaultAWSRegion -Scope 'Script' -Region $ProviderRegion
#endregion

#region Create the Devolutions AnyIdentity account
try {
    $iamUser = Get-IAMUser -UserName $AnyIdentityIAMUserName
    Write-Warning -Message "An IAM user called [$AnyIdentityIAMUserName] already exists."
} catch [Amazon.IdentityManagement.Model.NoSuchEntityException] {
    $iamUser = New-IAMUser -UserName $AnyIdentityIAMUserName -Force
}
# #endregion

# #region Create an access key for the Devolutions AnyIdentity account

if (-not ($iamAccessKey = Get-IAMAccessKey -UserName $AnyIdentityIAMUserName)) {
    $iamAccessKey = New-IAMAccessKey -UserName $AnyIdentityIAMUserName
} else {
    Write-Warning -Message "The user [$($AnyIdentityIAMUserName)] already has an access key. AWS does not allow retrieving the secret access key from an existing key."
}
#endregion

#region Create the user policy and attach to the user
$userPolicy = createPolicy 'UserPermission' $UserPermissionPolicyName $iamUser.Arn
Register-IAMUserPolicy -PolicyArn $userPolicy.Arn -UserName $AnyIdentityIAMUserName
#endregion

#region Create the role permission policy and the role

#region Create the user role's permission boundary policy
$permissionsBoundary = createPolicy 'PermissionsBoundary' $PermissionBoundaryPolicyName
#endregion

$rolePermissionPolicy = createPolicy 'RolePermission' $RolePermissionPolicyName

try {
    $iamRole = Get-IAMRole -RoleName $AnyIdentityIAMRoleName
    Write-Warning -Message "An IAM role called [$AnyIdentityIAMRoleName] already exists."
} catch [Amazon.IdentityManagement.Model.NoSuchEntityException] {

    Write-Host 'Giving AWS a chance to catch up before creating role for 20 seconds...'
    Start-Sleep -Seconds 20
    $trustPolicy = (Get-Content -Path "$PSScriptRoot\policies\RoleTrust.json" -Raw).replace('<user arn here>', $iamUser.Arn)

    $newIamRoleParams = @{
        RoleName                 = $AnyIdentityIAMRoleName
        AssumeRolePolicyDocument = $trustPolicy
        PermissionsBoundary      = $permissionsBoundary.Arn
    }
    $iamRole = New-IAMRole @newIamRoleParams
    
} finally {
    Register-IAMRolePolicy -PolicyArn $rolePermissionPolicy.Arn -RoleName $AnyIdentityIAMRoleName
}
#endregion

#region Return all of the necessary attributes to use in the other provider scripts
[pscustomobject]@{
    UserAccessKeyId     = $iamAccessKey.AccessKeyId
    UserSecretAccessKey = $iamAccessKey.SecretAccessKey
    RoleArn             = $iamRole.Arn
}

Write-Host 'Document these values as you will need them to use the AnyIdentity provider in DVLS!' -ForegroundColor Red
#endregion