#requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.1.540'}
#requires -Modules @{ModuleName='AWS.Tools.SecurityToken';ModuleVersion='4.1.540'}
#requires -Modules @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.1.540'}

<#
.SYNOPSIS
Creates an AWS IAM role with specific permissions for use by the Devolutions AnyIdentity provider.

.DESCRIPTION
This script sets up an AWS IAM role for use with Devolutions AnyIdentity provider, applying a permissions boundary and a specific permission policy to the role. It supports specifying an AWS region, IAM user ARN, and custom names for the IAM role and associated policies.

.PARAMETER ProviderRegion
The AWS region where the IAM role will be created.

.PARAMETER ProviderIAMAccessKey
The AWS access key (as a secure string) used for authentication. This key should have permissions to create roles and policies.

.PARAMETER ProviderIAMSecretAccessKey
The AWS secret access key (as a secure string) corresponding to the ProviderIAMAccessKey.

.PARAMETER ProviderIAMUserArn
The ARN of the AWS IAM user that will assume the role. This is used in the role's trust policy.

.PARAMETER AnyIdentityIAMRoleName
(Optional) The name of the IAM role to be created. Defaults to 'IAMChangeAllAccessKeys'.

.PARAMETER PermissionBoundaryPolicyName
(Optional) The name of the permission boundary policy to be attached to the IAM role. Defaults to 'IAMChangeIAMAccessKeysPermissionBoundary'.

.PARAMETER RolePermissionPolicyName
(Optional) The name of the permission policy to be attached to the IAM role. Defaults to 'IAMChangeIAMAccessKeysRole'.

.EXAMPLE
PS> .\setup.ps1 -ProviderRegion 'us-east-1' -ProviderIAMAccessKey (ConvertTo-SecureString 'YourAccessKey' -AsPlainText -Force) -ProviderIAMSecretAccessKey (ConvertTo-SecureString 'YourSecretKey' -AsPlainText -Force) -ProviderIAMUserArn 'arn:aws:iam::123456789012:user/YourIAMUser'

Creates an IAM role with default names for the role and policies in the 'us-east-1' AWS region, using the provided IAM user ARN for the role's trust policy.

.NOTES
Requires AWS PowerShell module AWS.Tools.IdentityManagement version 4.1.540 or newer.
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

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProviderIAMUserArn,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AnyIdentityIAMRoleName = 'IAMChangeAllAccessKeys',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PermissionBoundaryPolicyName = 'IAMChangeIAMAccessKeysPermissionBoundary',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RolePermissionPolicyName = 'IAMChangeIAMAccessKeysRole'
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

#region Authenticate to AWS using the IAM access key with permission to set up the role
$initialAuthsetCredParams = @{
    AccessKey = (decryptPassword($ProviderIAMAccessKey))
    SecretKey = (decryptPassword($ProviderIAMSecretAccessKey))
    Scope     = 'Script'
}
Set-AWSCredential @initialAuthsetCredParams

Set-DefaultAWSRegion -Scope 'Script' -Region $ProviderRegion
#endregion

## Create the role's permission boundary policy
$permissionsBoundary = createPolicy 'PermissionsBoundary' $PermissionBoundaryPolicyName

## Create the role's permission policy
$rolePermissionPolicy = createPolicy 'RolePermission' $RolePermissionPolicyName

## Create the role
try {
    $iamRole = Get-IAMRole -RoleName $AnyIdentityIAMRoleName
    Write-Warning -Message "An IAM role called [$AnyIdentityIAMRoleName] already exists."
} catch [Amazon.IdentityManagement.Model.NoSuchEntityException] {

    $trustPolicy = (Get-Content -Path "$PSScriptRoot\policies\RoleTrust.json" -Raw).replace('<user arn here>', $ProviderIAMUserArn)

    $newIamRoleParams = @{
        RoleName                 = $AnyIdentityIAMRoleName
        AssumeRolePolicyDocument = $trustPolicy
        PermissionsBoundary      = $permissionsBoundary.Arn
    }
    $iamRole = New-IAMRole @newIamRoleParams
    
} finally {
    ## Attach the role's permission poicy to the role
    Register-IAMRolePolicy -PolicyArn $rolePermissionPolicy.Arn -RoleName $AnyIdentityIAMRoleName
}
#endregion

#region Return all of the necessary attributes to use in the other provider scripts
# [pscustomobject]@{
    # UserAccessKeyId     = $iamAccessKey.AccessKeyId
    # UserSecretAccessKey = $iamAccessKey.SecretAccessKey
#     RoleArn             = $iamRole.Arn
# }

Write-Host "Document this role ARN as you will need it to set up the AnyIdentity provider in DVLS: $($iamRole.Arn)"
#endregion